"""Hermes as a collector: its own browser tool calls and the user's chat corrections, recorded into ``mordred.db``.

Phase B2 of the browser-history design. Three hooks:

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
  session (:func:`.history.last_hermes_call`, through the gated reader). While
  the session has no snapshot in this process, it also takes the field kinds of
  the newest browser snapshot in ``conversation_history`` (:func:`_seed_kinds`,
  below). The hook first writes the previous turn's held text (below) when that
  turn got no ``post_llm_call``, and returns ``None``: the message reaches the
  model unchanged.
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
- ``post_llm_call`` (:func:`post_llm_call`) ends the turn: it writes the turn's
  held text (below). Hermes fires it once per turn with a final response, not
  for an interrupted turn.

Episodes: one per ``(session, turn)`` with browser calls. Once its first call is
recorded, the turn's message becomes the episode's ``boundary`` /
``task_start`` (time: the turn's start), ``actor`` ``human`` for a person's
message (:func:`.history.speaks_for_user` then counts it as the user's words)
and ``agent`` otherwise. A task start names no page, so while
``excluded_sites`` is configured the receiver stores an ``agent`` one without
its text (``page_host_unknown``, :mod:`.contracts`). A correction joins the episode of the call it
corrects, as ``user_correction`` / ``human`` / ``correction``. A person's
correction message is never a task start: the browser calls of its turn join
the corrected episode while that is still the session's last episode, and
otherwise start an episode without a task start.

The turn's own text (its task start or correction) is held in memory until
the turn ends (``post_llm_call``, else the session's next ``pre_llm_call``) and
only then written, after the turn's calls. Before it is written, every value
the session's ``browser_type`` calls typed that may be a secret is replaced
with ``redacted`` (:func:`.contracts.redact_values`: as a whole word, compared
without case, also inside a URL; exclusion ``text_secrets_redacted``), whatever
the phrasing: a password the message named in words the free-text redactor
cannot read never reaches the store. A typed value may be a secret unless the
session's most recent snapshot, stale or not, names its field as one that is no
secret (``textbox "Note"``; :func:`_known_kind`): a field named as secret, one
naming nothing and one that snapshot does not list (refs are numbered per
snapshot, so an older page's kind says nothing) fail closed, and a value the
turn's message names as a secret or one that
:func:`.contracts.looks_like_secret` always counts. So a note typed after Enter
into a field last seen as ``textbox "Note"`` leaves the message intact (live B2
re-run, N1), while a plain password typed after a click into a field last seen
as a password field is scrubbed. A new process (``--resume``, ``-c``, a restart)
has no snapshot while the transcript hands Hermes the old page's refs (B2 final
live check, M1 and M2): until its first snapshot, each turn's start takes the
kinds of the newest snapshot in the transcript (:func:`_seed_kinds`; never
lowering a kind the session knows), so a value typed into the transcript's
``searchbox "Search"`` stays in the user's words and a password typed into its
password field does not. Values of at least :data:`MIN_SCRUBBED_CHARS`
characters count; the session keeps the last :data:`MAX_WITHHELD_VALUES` in
memory only, never stored. While Hermes's capture is off, every value typed
during a held correction's turn counts (no field can be classified). A value the turn's message names as a secret
(:func:`.contracts.secret_values`, "type X as the password") is also withheld
from the store when Hermes types it into any field, ``typed_text_dropped``
(N5). Those values are bounded (at most :data:`.contracts.MAX_SECRET_VALUES`,
each at most :data:`.contracts.MAX_SECRET_VALUE_CHARS` characters); a message
that names more fails closed: every value typed in its turn is withheld and
counts. A held text is dropped when its turn never ends (an interrupted
last turn, a process that exits, a session forgotten), when recording it is off
at the turn's end, or when the session is suspended, and a refused write is not
retried; the turn's calls then stay in their episode without it. The store is
append-only: a text already stored is never rewritten, so a value withheld only
in a later turn is not scrubbed from an earlier turn's stored text.
The episodes a session recorded are its own work, already in its conversation:
the history hooks leave them out of their blocks, those of this process from
memory (:func:`own_episodes`) and those of any process (``--resume``, ``-c``,
a restart) from the store, by the principal and the session id on their
events (:func:`own_session`).

Typed text (:func:`field_kind`, :func:`_typed_kind`): a ref line naming a
password (English or Japanese), secret, token, card, one-time code or PIN is
``sensitive`` and its text is never sent; a line naming nothing is ``other``
and a named field ``text``, both kept (owner decision 2026-10-22). A ref the
session's most recent snapshot does not list (before the session's first
snapshot too) and a target that is no ref are ``sensitive``, as for the scrub
(B2 final live check, M2: after ``--resume`` a password typed into the
transcript's password-field ref was stored as ``other``). While the
snapshot is stale (below) the field is ``sensitive``: its line may describe
another page. The receiver's value check still withholds anything that
:func:`.contracts.looks_like_secret`. Either way the withheld value is scrubbed
from the turn's text (above). A single character pressed with
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

Failure behavior: no hook ever raises ``Exception`` or changes the call or the
turn. Work per call is bounded (one receiver call of one event; a turn's end
writes at most one more event; a correction without a call this process
recorded first reads the store once, :func:`.history.last_hermes_call`, and goes
on without it when that read is refused or fails; the snapshot kept for ref
lookup is capped at :data:`MAX_SNAPSHOT_CHARS`; a turn's start reads at most the
last :data:`MAX_SEED_MESSAGES` messages of the transcript and :data:`MAX_SEED_CHARS`
characters of browser results in them; at most
:data:`MAX_SESSIONS` sessions are remembered). A write waits at most
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
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ._browser_results import (
    PAGE_TEXT_CHARS,
    element_label,
    field_kind,
    most_sensitive_kind,
    page_text,
    ref_kinds,
    ref_line,
    ref_token,
    transcript_result,
)
from ._browser_results import json_object as _json_object
from ._browser_results import page_location as _page
from ._browser_results import reported_url as _reported_url
from ._browser_results import text_field as _text_field
from .contracts import (
    COLLECTOR_SENSITIVE_MARK,
    EXCLUSION_TEXT_SECRETS,
    EXCLUSION_TYPED_TEXT,
    MAX_TARGET_CHARS,
    MAX_TEXT_CHARS,
    SCHEMA_VERSION,
    SENSITIVE_FIELD_KIND,
    ContractError,
    PeerPrincipal,
    SecretValues,
    canonical_json,
    check_batch_envelope,
    contains_values,
    event_size,
    looks_like_secret,
    normalize_event,
    redact_values,
    secret_values,
)

if TYPE_CHECKING:
    from .config import ActivityConfig
    from .history import HermesSession
    from .store import ActivityStore

__all__ = [
    "MAX_SEED_CHARS",
    "MAX_SEED_MESSAGES",
    "MAX_SESSIONS",
    "MAX_SNAPSHOT_CHARS",
    "MAX_WITHHELD_VALUES",
    "MIN_SCRUBBED_CHARS",
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
    "own_session",
    "page_text",
    "post_llm_call",
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
#: A typed value the store did not keep is replaced in the turn's texts from this many characters on (a
#: shorter one would replace parts of ordinary words; :func:`_scrubbed`).
MIN_SCRUBBED_CHARS: Final = 4
#: Withheld typed values a session remembers, in memory only, for :func:`_scrubbed` (oldest forgotten first).
MAX_WITHHELD_VALUES: Final = 32
#: A turn whose message names no secret (or that has no message).
_NO_SECRETS: Final = SecretValues((), complete=True)
#: Refs of the session's most recent snapshot whose field kind it remembers (the first ones forgotten first).
MAX_REF_KINDS: Final = 1024
#: A session without a snapshot in this process reads its transcript (``conversation_history``) from the end for
#: the field kinds of its refs (:func:`_seed_kinds`): at most this many messages (and as many tool calls of each)
MAX_SEED_MESSAGES: Final = 256
#: and this many characters of the browser results among them (two of :data:`._browser_results.MAX_RESULT_CHARS`).
MAX_SEED_CHARS: Final = 2_000_000
#: The field kind of a named field that is no secret (:func:`._browser_results.field_kind`).
_PLAIN_FIELD_KIND: Final = "text"
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


@dataclass(frozen=True)
class _Held:
    """A turn's own text, kept in memory until the turn ends (:func:`_flush`): its task start, or (``attempt``
    set) its correction of that call."""

    turn: str | None
    episode: str
    refs: Mapping[str, str | None]
    text: str
    at: float
    human: bool = False
    cut: bool = False
    attempt: _Attempt | None = None


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
    #: The current turn's task start or correction, written when the turn ends (:func:`_flush`).
    held: _Held | None = None
    #: Values typed in this session that the store did not keep (a secret field, or a value that looks like a
    #: secret); replaced in the session's turn texts before they are written (:func:`_scrubbed`). Memory only.
    withheld: collections.deque[str] = field(default_factory=lambda: collections.deque(maxlen=MAX_WITHHELD_VALUES))
    #: The values the current turn's message names as secrets (:func:`.contracts.secret_values`): typed into any
    #: field they are withheld; while the list is incomplete, every value typed in the turn is. Memory only.
    turn_secrets: SecretValues = _NO_SECRETS
    #: The field kind of each ref of the session's most recent snapshot, stale or not (:func:`_known_kind`); in a
    #: new process, first those of the transcript's (:func:`_seed_kinds`).
    ref_kinds: dict[str, str] = field(default_factory=dict)
    #: A snapshot taken in this process set the kinds: the transcript is no longer read for them.
    snapshot_seen: bool = False
    slow: int = 0
    suspended: bool = False


#: A session's state key: the profile home's real path and Hermes's session (:func:`._history_access.session_key`).
_Key = tuple[str, str]
_sessions_lock = threading.Lock()
_sessions: collections.OrderedDict[_Key, _Session] = collections.OrderedDict()


def _state_key(home: Path, session_id: Any, task_id: Any) -> _Key:
    from . import _history_access as access

    return os.path.realpath(home), access.session_key(session_id, task_id)


def _existing_session(key: _Key) -> _Session | None:
    with _sessions_lock:
        return _sessions.get(key)


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


def own_session(home: Path, session_id: Any = None) -> HermesSession | None:
    """This Hermes session of ``home`` as the store knows it: the profile's principal and the session id this
    capture writes on its events, so the history hooks leave out the episodes the session recorded in any
    process (:func:`.history.episodes_for_sites` ``session``), not only those :func:`own_episodes` remembers;
    ``None`` without a session id the capture would record."""
    from .history import HermesSession

    session = _ref(session_id)
    return None if session is None else HermesSession(principal(home).peer_id, session)


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
    #: What was typed when the store will not keep it: scrubbed from the session's turn texts (:func:`_scrubbed`).
    withheld: str | None = None


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


def _known_kind(state: _Session, ref: Any) -> str:
    """The kind of ``ref``'s field in the session's most recent snapshot, stale or not (in a new process, first
    the transcript's: :func:`_seed_kinds`), shared by the typed text (:func:`_typed_kind`) and the scrub
    (:func:`_learns`). A ref that snapshot does not list (before the session's first snapshot too, one an older
    page listed, or one past a snapshot Hermes cut short) and a target that is no ref are ``sensitive``: fail
    closed (B2 final live check, M2)."""
    token = ref_token(ref)  # ``browser_type`` takes only a snapshot ref (0.13.0 and 0.19.0 require one)
    return state.ref_kinds.get(token, SENSITIVE_FIELD_KIND) if token is not None else SENSITIVE_FIELD_KIND


def _typed_kind(state: _Session, ref: Any) -> str:
    """The field kind that decides whether typed text is kept: ``sensitive`` while the snapshot is stale (its line
    may describe another page's field), else the field's known kind (:func:`_known_kind`)."""
    return SENSITIVE_FIELD_KIND if state.snapshot_stale else _known_kind(state, ref)


def _type(call: _Call, state: _Session) -> _Mapped:
    line = ref_line(state.snapshot, call.args.get("ref"))
    kind = _typed_kind(state, call.args.get("ref"))
    typed = call.args.get("text")
    typed = typed if isinstance(typed, str) and typed else None
    base = _on_page("type", state, target=element_label(line), args={"field_kind": kind})
    # A value the turn's message names as a secret ("type X as the password") is withheld from any field, and so is
    # every value typed in a turn whose message names more values than are listed (fail closed).
    secrets = state.turn_secrets
    named = typed is not None and (not secrets.complete or contains_values(typed, secrets.values))
    learned = typed if typed and _learns(state, call.args.get("ref"), typed, named) else None
    if kind != SENSITIVE_FIELD_KIND:
        if named:
            return replace(base, exclusions=(EXCLUSION_TYPED_TEXT,), withheld=learned)
        # The receiver withholds a value that looks like a secret whatever the field.
        return replace(base, text=typed, withheld=learned)
    # What is typed into a secret field (or a field the snapshot does not name, or a stale one) is never sent.
    marks = (COLLECTOR_SENSITIVE_MARK, EXCLUSION_TYPED_TEXT) if typed else (COLLECTOR_SENSITIVE_MARK,)
    return replace(base, exclusions=marks, withheld=learned)


def _learns(state: _Session, ref: Any, typed: str, named: bool) -> bool:
    """Whether a typed value is scrubbed from the turn's texts: unless the session's most recent snapshot, stale or
    not (:func:`_known_kind`), names its field as one that is no secret (``textbox "Note"``), it may be a
    password, so it is; a field that snapshot does not list or that names nothing fails closed. A value the
    message names as a secret, or one that looks like a secret, always is."""
    if named or looks_like_secret(typed):
        return True
    return _known_kind(state, ref) != _PLAIN_FIELD_KIND


def _note_kinds(state: _Session) -> None:
    """The snapshot just taken gives the field kinds (:func:`_known_kind`): those of every ref it writes, and no
    other (refs are numbered per snapshot, so an older page's kind says nothing about this page's field). It
    replaces what the transcript gave (:func:`_seed_kinds`), which is no longer read. Without a snapshot (the
    page may have changed) the kinds stay those of the last one, now stale."""
    if state.snapshot is None:
        return
    state.snapshot_seen = True
    state.ref_kinds = dict(ref_kinds(state.snapshot))
    _forget_kinds(state)


def _forget_kinds(state: _Session) -> None:
    while len(state.ref_kinds) > MAX_REF_KINDS:
        del state.ref_kinds[next(iter(state.ref_kinds))]


def _row_tool(row: Mapping[str, Any], names: Mapping[str, str]) -> str | None:
    """The tool of a transcript's tool row: its ``tool_name`` (0.19.0, also from ``state.db``) or ``name`` (a
    live message), else the assistant's tool call with its id (``names``, :func:`_tool_names`; the 0.13.0 floor
    stores no name on a tool row)."""
    for key in ("tool_name", "name"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    call_id = row.get("tool_call_id")
    return names.get(call_id) if isinstance(call_id, str) else None


def _tool_names(window: list[Any]) -> dict[str, str]:
    """``tool_call_id -> tool name`` of the assistant's tool calls in ``window``, the newest call of an id."""
    names: dict[str, str] = {}
    for message in window:
        tool_calls = message.get("tool_calls") if isinstance(message, Mapping) else None
        for tool_call in tool_calls[:MAX_SEED_MESSAGES] if isinstance(tool_calls, list) else ():
            function = tool_call.get("function") if isinstance(tool_call, Mapping) else None
            name = function.get("name") if isinstance(function, Mapping) else None
            if isinstance(name, str) and isinstance(tool_call.get("id"), str):
                names[tool_call["id"]] = name
    return names


def _transcript_snapshot(history: Any) -> str | None:
    """The snapshot of the newest successful page-reporting browser result in a transcript (the tools and the
    ``snapshot`` field :func:`_observe` reads), cut to :data:`MAX_SNAPSHOT_CHARS` like a live one; ``None`` when
    none is found in the last :data:`MAX_SEED_MESSAGES` messages within :data:`MAX_SEED_CHARS` characters of
    page-reporting results. A newer result that reports no snapshot (a click, a failed call) is passed over, as
    live; one that cannot be read (replaced, marked or cut short by Hermes) ends the search: the page it reported
    is unknown, so no older snapshot stands for it."""
    if not isinstance(history, list | tuple):
        return None
    window = list(history[max(0, len(history) - MAX_SEED_MESSAGES) :])
    names = _tool_names(window)
    budget = MAX_SEED_CHARS
    for row in reversed(window):
        if not isinstance(row, Mapping) or row.get("role") != "tool" or _row_tool(row, names) not in _REPORTS_PAGE:
            continue
        content = row.get("content")
        budget -= len(content) if isinstance(content, str) else 0
        payload = transcript_result(content)
        if payload is None or budget < 0:
            return None
        snapshot = _text_field(payload, "snapshot") if payload.get("success") is True else None
        if snapshot:
            return snapshot[:MAX_SNAPSHOT_CHARS]
    return None


def _seed_kinds(state: _Session, history: Any) -> None:
    """A session without a snapshot in this process (``--resume``, ``-c``, a restart, while the transcript hands
    Hermes the old page's refs; B2 final live check, M1 and M2) takes the field kinds of the newest snapshot in
    its transcript (:func:`_transcript_snapshot`), read by the parser of a live snapshot
    (:func:`._browser_results.ref_kinds`: a ref spoofed inside a name or value is ``sensitive``), and no other: a
    ref it does not list, or every ref without one, fails closed. A kind never lowers the one the session already
    knows for the ref. The kinds are stale: they never stand for the open page or name an element, and the first
    snapshot this process takes replaces them (:func:`_note_kinds`)."""
    known = state.ref_kinds
    seeded = ref_kinds(_transcript_snapshot(history))
    state.ref_kinds = {ref: most_sensitive_kind(known.get(ref, kind), kind) for ref, kind in seeded.items()}
    _forget_kinds(state)


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
        _note_kinds(state)
        if reported is not None:
            state.page_known, state.page_url = _page(reported)
        return
    state.page_known, state.page_url = _page(reported)
    state.snapshot, state.snapshot_stale = (snapshot[:MAX_SNAPSHOT_CHARS], False) if snapshot else (None, True)
    _note_kinds(state)


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


def _held_event(held: _Held, text: str, scrubbed: bool) -> dict[str, Any]:
    """The task start of ``held``'s episode, or (``held.attempt`` set) its correction, holding ``text``."""
    if held.attempt is None:
        event = _envelope(held.episode, held.refs, phase="boundary", at=held.at)
        event.update(actor="human" if held.human else "agent", action={"op": "task_start"}, text=text)
        event["quality"]["truncated"] = held.cut
    else:
        event = _correction_event(held.attempt, text, held.refs, at=held.at)
    if scrubbed:
        event["quality"]["exclusions"] = [EXCLUSION_TEXT_SECRETS]
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


def _correction_event(attempt: _Attempt, body: str, refs: Mapping[str, str | None], *, at: float) -> dict[str, Any]:
    event = _envelope(attempt.episode_id, refs, phase="correction", at=at)
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
    every batch and every event. A failure part-way returns
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
# A turn's own text: held until the turn ends, scrubbed of withheld values
# --------------------------------------------------------------------------- #


def _remember(state: _Session, value: str | None) -> None:
    """Keep a typed value the store will not keep (stripped) to scrub it from the session's turn texts."""
    value = value.strip() if isinstance(value, str) else ""
    if MIN_SCRUBBED_CHARS <= len(value) <= MAX_TEXT_CHARS and value not in state.withheld:
        state.withheld.append(value)


def _scrubbed(text: str, values: Iterable[str]) -> tuple[str, bool]:
    """``(text with every withheld value replaced by`` :data:`.contracts.REDACTED` ``, anything replaced)``:
    whole words compared without case, longest value first, never inside a URL's scheme or host, independent
    of any phrasing (:func:`.contracts.redact_values`)."""
    return redact_values(text, values)


def _flush(state: _Session, home: Path, config: ActivityConfig) -> None:
    """The turn ended: write its held task start or correction, scrubbed of the session's withheld values
    (exclusion ``text_secrets_redacted`` when one was found). Dropped while recording it is off or the session is
    suspended; never retried."""
    held, state.held = state.held, None
    if held is None or state.suspended:
        return
    if not (_correcting(config) if held.attempt is not None else _capturing(config)):
        return
    text, scrubbed = _scrubbed(held.text, state.withheld)
    _write(state, home, config, [_held_event(held, text, scrubbed)])


def _drop_held(key: _Key) -> None:
    state = _existing_session(key)
    if state is not None:
        with state.lock:
            state.held = None


def _remember_unrecorded(key: _Key, args: Any) -> None:
    """A ``browser_type`` while Hermes's capture is off cannot be classified: its value is remembered while a
    correction is held, so the correction never keeps it (fail closed)."""
    state = _existing_session(key)
    if state is None or not isinstance(args, Mapping):
        return
    with state.lock:
        if state.held is not None:
            _remember(state, args.get("text"))


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
    """``(episode id, whether its task start is still to be held)`` for a browser call of ``turn``; the task
    start needs the turn's message, so a call of a turn whose ``pre_llm_call`` was not seen gets none.

    A correction turn's calls join the corrected episode while it is still the session's last one (it has its
    task start); otherwise, or when no correction is held for the turn, they start an episode without one (the
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
        if _correcting(config) and tool_name == "browser_type":
            _remember_unrecorded(_state_key(home, session_id, task_id), args)
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
        _remember(state, mapped.withheld)
        if _unplaced(config, mapped):
            _LOG.debug("mordred activity capture: call dropped (source_excluded: the page is unknown)")
            return
        if not _write(state, home, config, [_call_event(call, mapped, episode, refs)]):
            return
        if episode not in state.episodes:
            state.episodes.append(episode)
        state.last = _Attempt(call.attempt_id, episode, mapped.route)
        if pending and state.message is not None:
            # The episode has its call: the task start waits for the turn's end (:func:`_flush`).
            state.task_recorded = True
            state.held = _Held(
                turn, episode, refs, state.message, state.turn_at, human=state.human, cut=state.message_cut
            )


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


def _record_turn(
    user_message: Any, session_id: Any, task_id: Any, turn_id: Any, platform: Any, history: Any = None
) -> None:
    from . import _history_access as access

    home = access.home()
    config = access.config(home)
    key = _state_key(home, session_id, task_id)
    if not (_capturing(config) or _correcting(config)):
        _drop_held(key)
        return
    state = _session(key)
    with state.lock:
        _flush(state, home, config)  # the previous turn is over (an interrupted turn gets no post_llm_call)
        if _capturing(config) and not state.snapshot_seen:
            try:
                _seed_kinds(state, history)
            except Exception as exc:  # an unreadable transcript gives no kinds: its refs fail closed
                _LOG.debug("mordred activity capture: transcript kinds skipped (%s)", type(exc).__name__)
        human = speaks_as_user(config, platform)
        body = correction_text(user_message) if human else None
        # A correction is never the turn's task: its browser calls get no task start (:func:`_episode_for`).
        _begin_turn(state, None if body is not None else user_message, turn_id, human)
        state.turn_secrets = secret_values(user_message) if isinstance(user_message, str) else _NO_SECRETS
        if body is None or not _correcting(config) or state.suspended:
            return
        attempt = state.last or _stored_last(home, config, state, session_id)
        if attempt is None:
            return
        # Written when the turn ends, like a task start; the turn's browser calls join the corrected episode.
        refs = _refs(session_id, state.turn_ref)
        state.held = _Held(state.turn, attempt.episode_id, refs, body, state.turn_at, attempt=attempt)
        state.joins = attempt.episode_id


def pre_llm_call(
    user_message: Any = None,
    session_id: Any = None,
    task_id: Any = None,
    turn_id: Any = None,
    platform: Any = None,
    conversation_history: Any = None,
    **_kwargs: Any,
) -> None:
    """Remember the turn and record a chat correction (``task_id``, ``turn_id`` and ``platform`` are read when
    Hermes passes them); while the session has no snapshot in this process, take the field kinds of the newest
    snapshot in ``conversation_history`` when Hermes passes it (:func:`_seed_kinds`). Always returns ``None``
    (the message goes to the model unchanged), never raises ``Exception``."""
    try:
        _record_turn(user_message, session_id, task_id, turn_id, platform, conversation_history)
    except Exception as exc:  # recording must never abort the turn
        _LOG.debug("mordred activity capture: turn skipped (%s)", type(exc).__name__)


def _end_turn(session_id: Any, task_id: Any, turn_id: Any) -> None:
    from . import _history_access as access

    home = access.home()
    state = _existing_session(_state_key(home, session_id, task_id))
    if state is None:
        return
    config = access.config(home)
    with state.lock:
        held = state.held
        # Another turn's end (Hermes's turn id differs) leaves the text for its own turn's end.
        if held is None or (isinstance(turn_id, str) and turn_id and held.turn != turn_id):
            return
        _flush(state, home, config)


def post_llm_call(session_id: Any = None, task_id: Any = None, turn_id: Any = None, **_kwargs: Any) -> None:
    """The turn is over: write its held task start or correction (:func:`_flush`; ``task_id`` and ``turn_id``
    are read when Hermes passes them, 0.13.0 passes neither); never raises ``Exception`` and returns nothing."""
    try:
        _end_turn(session_id, task_id, turn_id)
    except Exception as exc:  # recording must never break the turn
        _LOG.debug("mordred activity capture: turn end skipped (%s)", type(exc).__name__)


def register_hooks(ctx: Any) -> None:
    """Register the three hooks; registration never reads configuration or opens the store."""
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("post_llm_call", post_llm_call)
