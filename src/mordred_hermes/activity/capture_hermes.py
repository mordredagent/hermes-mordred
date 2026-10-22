"""Hermes as a collector: its own browser tool calls and the user's chat corrections, recorded into ``mordred.db``.

Phase B2 of the browser-history design. Two hooks:

- ``pre_llm_call`` (:func:`pre_llm_call`) remembers the turn per Hermes
  session: its id (Hermes's ``turn_id``; hermes-agent 0.13.0 passes none, so a
  local id is made for every call), when it started, the user message (at most
  :data:`.contracts.MAX_TEXT_CHARS` characters) and whether that message is a
  person's words: a turn whose ``platform`` is ``subagent`` (a delegated
  task) or ``cron`` (a scheduled job) carries an agent's or a job's prompt
  instead. A person's message starting with ``correct:`` or ``訂正:`` (also
  with a full-width colon; the operator's convention, any case) also records
  a correction of the session's last recorded browser call. The hook returns
  ``None``: the message reaches the model unchanged.
- ``post_tool_call`` (:func:`post_tool_call`) turns every ``browser_*`` call
  into one event with ``source`` ``hermes``, ``actor`` ``agent``, the Hermes
  session and turn ids and ``attempt_id`` derived from ``tool_call_id``
  (:func:`attempt_id`). ``browser_navigate`` → ``navigate`` (route from the
  final URL; ``page_title`` from the result; ``page_text`` = the first
  :data:`PAGE_TEXT_CHARS` characters of its ``snapshot``), ``browser_click``
  → ``click``, ``browser_type`` → ``type``, ``browser_press`` → ``key``,
  ``browser_scroll`` → ``scroll``, ``browser_back`` → ``back``; any other
  browser tool → ``other`` with the tool name as its target. A click or type
  names its element by the ref's line in the session's last snapshot
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
``correction``.

Typed text (:func:`field_kind`): a ref line naming a password (English or
Japanese), secret, token, card, one-time code or PIN is ``sensitive`` and its
text is never sent; a missing line, or one naming nothing, is ``other`` and a
named field ``text``, both kept (owner decision 2026-10-22). The receiver's
value check still withholds anything that :func:`.contracts.looks_like_secret`.
A single character pressed with ``browser_press`` is typing too and is not kept.

Writes go through the receiver (:class:`.ingest.StoreReceiver`) as the
in-process principal ``hermes:<profile>`` (producer kind ``hermes``, trust
``local``, permitted use ``learning``), so configuration, the contract, size
limits, secret redaction, excluded sites, episode ownership and the protection
gate (SQLCipher only) apply unchanged; nothing leaves the process. Recording
needs ``enabled``, ``collection_enabled``, the master switch ``history_enabled``
and ``history_capture_hermes`` (corrections: ``history_chat_corrections``);
an invalid ``excluded_sites`` is refused by the receiver as usual.

Failure behavior: neither hook ever raises ``Exception`` or changes the call or
the turn. Work per call is bounded (one receiver call of one or two events; the
snapshot kept for ref lookup is capped at :data:`MAX_SNAPSHOT_CHARS`; at most
:data:`MAX_SESSIONS` sessions are remembered). A write waits at most
:data:`WRITE_BUSY_S` for another writer's lock (the extension gateway's
receiver writes the same store) and is then refused as ``busy`` and dropped. A
write that takes longer than :data:`SLOW_APPEND_S` counts as slow; after
:data:`SLOW_APPENDS_TO_SUSPEND` slow writes recording stops for that session
and ``activity.capture_suspended`` is audited.

Known limit: the page host of a click, type or key is the last one Hermes saw
(a navigate or back result, or a snapshot that reports its URL); a page that a
click reached is attributed to the previous host until then.
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
from urllib.parse import urlsplit

from .contracts import (
    COLLECTOR_SENSITIVE_MARK,
    EXCLUSION_TYPED_TEXT,
    MAX_TARGET_CHARS,
    MAX_TEXT_CHARS,
    SCHEMA_VERSION,
    SENSITIVE_FIELD_KIND,
    ContractError,
    PeerPrincipal,
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
    "post_tool_call",
    "pre_llm_call",
    "principal",
    "ref_line",
    "register_hooks",
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
#: Characters of a navigation's snapshot stored as its page text (:data:`.contracts.MAX_PAGE_TEXT_CHARS`).
PAGE_TEXT_CHARS: Final = 8000
#: Characters of the session's last snapshot kept for ref lookup.
MAX_SNAPSHOT_CHARS: Final = 60_000
#: Hermes sessions remembered (oldest forgotten first).
MAX_SESSIONS: Final = 128
MAX_REF_LINE_CHARS: Final = 400
MAX_URL_CHARS: Final = 4096
#: Results larger than this are not parsed (:data:`.hooks_history.MAX_RESULT_CHARS`).
MAX_RESULT_CHARS: Final = 1_000_000
#: Hermes platforms whose "user message" is not a person's words.
NON_HUMAN_PLATFORMS: Final = frozenset({"subagent", "cron"})
#: ``correct: …`` / ``訂正: …`` (also with a full-width colon; the operator's convention, ``mordred/app.py``),
#: any case.
CORRECTION_RE: Final = re.compile(r"^\s*(?:訂正\s*[:\uff1a]|correct\s*:)\s*(.*)$", re.IGNORECASE | re.DOTALL)
#: A ref line naming a secret field: password (also German ``Passwort``), passcode, passphrase, passkey, PIN,
#: one-time code, OTP, 2FA/MFA, secret, token, card, card security code, verification or authentication code,
#: and the Japanese words for these.
_SENSITIVE_FIELD_RE: Final = re.compile(
    r"(?i)pass(?:w|code|phrase|key)|(?<![a-z])(?:pwd|otp|pin|cvc|cvv|csc|2fa|mfa)(?![a-z])"
    r"|(?<![a-z])(?:secret|token|card)|one[\s_-]?time|security[\s_-]?code|verification[\s_-]?code"
    r"|auth(?:entication|orization)?[\s_-]?code"
    r"|パスワード|暗証番号|パスコード|ワンタイム|認証コード|確認コード|セキュリティコード|カード|秘密|トークン"
)
#: A tool's ``ref`` argument (``@e5`` or ``e5``).
_REF_TOKEN_RE: Final = re.compile(r"@?([A-Za-z][A-Za-z0-9_-]{0,31})")
#: An accessibility line's role and quoted accessible name (``- textbox "Email" [ref=e3]: value``).
_NAMED_LINE_RE: Final = re.compile(r'^[\s*-]*(?P<role>[A-Za-z][\w-]{0,40})\s+"(?P<name>(?:[^"\\\n]|\\.){1,300})"')
_ANNOTATION_RE: Final = re.compile(r"\[[^\]\n]{0,200}\]")
#: The receiver's identifier rules (``contracts._ID_RE`` / ``contracts._REF_RE`` / ``contracts._HOST_RE``).
_ID_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}")
_SESSION_REF_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HOST_RE: Final = re.compile(r"[a-z0-9.:-]{1,253}")
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
    url: str | None


@dataclass
class _Session:
    lock: threading.Lock = field(default_factory=threading.Lock)
    #: The current turn's key (Hermes's ``turn_id``, else a local one) and Hermes's own id when it gave one.
    turn: str | None = None
    turn_ref: str | None = None
    turn_at: float = 0.0
    message: str | None = None
    message_cut: bool = False
    human: bool = True
    episode: str | None = None
    episode_turn: str | None = None
    task_recorded: bool = False
    #: The last browser call that was recorded: what a chat correction refers to.
    last: _Attempt | None = None
    page_url: str | None = None
    snapshot: str | None = None
    slow: int = 0
    suspended: bool = False


_sessions_lock = threading.Lock()
_sessions: collections.OrderedDict[str, _Session] = collections.OrderedDict()


def _session(key: str) -> _Session:
    with _sessions_lock:
        state = _sessions.get(key)
        if state is None:
            state = _sessions[key] = _Session()
        _sessions.move_to_end(key)
        while len(_sessions) > MAX_SESSIONS:
            _sessions.popitem(last=False)
        return state


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


def _ref(value: Any) -> str | None:
    """A Hermes session or turn id as the receiver accepts it, else ``None`` (never a made-up id)."""
    return value if isinstance(value, str) and _SESSION_REF_RE.fullmatch(value) else None


def _url(value: Any) -> str | None:
    """An ``http(s)`` URL with an ASCII host, else ``None`` (``about:blank``, ``file:``, ``chrome:`` pages)."""
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_URL_CHARS:
        return None
    text = value.strip()
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host or not _HOST_RE.fullmatch(host):
        return None
    return text


def correction_text(message: Any) -> str | None:
    """The correction in a ``correct: …`` / ``訂正: …`` message, else ``None`` (also for an empty one)."""
    if not isinstance(message, str):
        return None
    match = CORRECTION_RE.match(message)
    body = match.group(1).strip() if match else ""
    return body[:MAX_TEXT_CHARS] or None


def _line_at(snapshot: str, start: int, end: int) -> str:
    first = snapshot.rfind("\n", 0, start) + 1
    last = snapshot.find("\n", end)
    return snapshot[first : len(snapshot) if last == -1 else last].strip()[:MAX_REF_LINE_CHARS]


def _ref_position(snapshot: str, token: str) -> tuple[int, int] | None:
    """Where ``ref=<token>`` (agent-browser) or ``[<token>]`` stands, not as a prefix of a longer ref."""
    for needle in (f"ref={token}", f"[{token}]"):
        start = 0
        while (pos := snapshot.find(needle, start)) != -1:
            end = pos + len(needle)
            if needle.startswith("[") or not (_continues(snapshot, end) or _continues(snapshot, pos - 1)):
                return pos, end
            start = end
    return None


def _continues(text: str, index: int) -> bool:
    """``text[index]`` would make a ``ref=…`` match part of a longer word (``xref=e4``, ``ref=e40``)."""
    return 0 <= index < len(text) and (text[index].isalnum() or text[index] in "_-")


def ref_line(snapshot: str | None, ref: Any) -> str | None:
    """The snapshot line of element ``ref`` (``@e5`` / ``e5``), stripped and bounded; ``None`` when absent."""
    if not snapshot or not isinstance(ref, str):
        return None
    match = _REF_TOKEN_RE.fullmatch(ref.strip())
    if match is None:
        return None
    found = _ref_position(snapshot, match.group(1))
    return None if found is None else _line_at(snapshot, *found) or None


def _label_parts(line: str) -> tuple[str, bool]:
    """``(label, names something)``: role and quoted name, else the line before its value without annotations."""
    named = _NAMED_LINE_RE.match(line)
    if named is not None:
        return f'{named.group("role")} "{named.group("name")}"', True
    head = " ".join(_ANNOTATION_RE.sub(" ", line).split(":", 1)[0].split()).strip(" *-")
    words = [word for word in head.split() if any(char.isalnum() for char in word)]
    return head, len(words) > 1


def element_label(line: str | None) -> str | None:
    """How an event names an element: its role and accessible name (``textbox "Email"``), never its value."""
    if not line:
        return None
    label = _label_parts(line)[0]
    return label[:MAX_TARGET_CHARS] or None


def field_kind(line: str | None) -> str:
    """``sensitive`` when the ref line names a secret field, ``other`` when it is missing or names nothing,
    else ``text``."""
    if not line:
        return "other"
    if _SENSITIVE_FIELD_RE.search(line):
        return SENSITIVE_FIELD_KIND
    return "text" if _label_parts(line)[1] else "other"


def _json_object(result: Any) -> dict[str, Any] | None:
    if not isinstance(result, str) or len(result) > MAX_RESULT_CHARS:
        return None
    try:
        payload = json.loads(result)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _text_field(payload: Mapping[str, Any] | None, key: str) -> str | None:
    value = payload.get(key) if payload is not None else None
    return value if isinstance(value, str) and value else None


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


def _navigate(call: _Call, state: _Session) -> _Mapped:
    del state
    if not call.succeeded:  # nothing opened: the URL that was asked for, no page fields
        return _Mapped("navigate", route=_url(call.args.get("url")))
    snapshot = _text_field(call.payload, "snapshot")
    return _Mapped(
        "navigate",
        route=_url(_text_field(call.payload, "url")) or _url(call.args.get("url")),
        page_title=_text_field(call.payload, "title"),
        page_text=snapshot[:PAGE_TEXT_CHARS] if snapshot else None,
    )


def _click(call: _Call, state: _Session) -> _Mapped:
    return _Mapped("click", route=state.page_url, target=element_label(ref_line(state.snapshot, call.args.get("ref"))))


def _type(call: _Call, state: _Session) -> _Mapped:
    line = ref_line(state.snapshot, call.args.get("ref"))
    kind = field_kind(line)
    typed = call.args.get("text")
    typed = typed if isinstance(typed, str) and typed else None
    base = _Mapped("type", route=state.page_url, target=element_label(line), args={"field_kind": kind})
    if kind != SENSITIVE_FIELD_KIND:
        return replace(base, text=typed)
    # What is typed into a secret field never leaves this function.
    marks = (COLLECTOR_SENSITIVE_MARK, EXCLUSION_TYPED_TEXT) if typed else (COLLECTOR_SENSITIVE_MARK,)
    return replace(base, exclusions=marks)


def _press(call: _Call, state: _Session) -> _Mapped:
    key = call.args.get("key")
    if isinstance(key, str) and 1 < len(key) <= 32:  # Enter, Tab, Control+a: named keys are kept
        return _Mapped("key", route=state.page_url, args={"keys": [key]})
    # A single character pressed is typing into a field Hermes cannot classify here.
    marks = (EXCLUSION_TYPED_TEXT,) if isinstance(key, str) and key else ()
    return _Mapped("key", route=state.page_url, exclusions=marks)


def _scroll(call: _Call, state: _Session) -> _Mapped:
    direction = call.args.get("direction")
    args = {"direction": direction} if isinstance(direction, str) and 0 < len(direction) <= 16 else {}
    return _Mapped("scroll", route=state.page_url, args=args)


def _back(call: _Call, state: _Session) -> _Mapped:
    landed = _url(_text_field(call.payload, "url")) if call.succeeded else None
    return _Mapped("back", route=landed or state.page_url)


def _other(call: _Call, state: _Session) -> _Mapped:
    return _Mapped("other", route=state.page_url, target=call.tool[:MAX_TARGET_CHARS])


_MAPPERS: Final[Mapping[str, Callable[[_Call, _Session], _Mapped]]] = {
    "browser_navigate": _navigate,
    "browser_click": _click,
    "browser_type": _type,
    "browser_press": _press,
    "browser_scroll": _scroll,
    "browser_back": _back,
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


def _observe(call: _Call, state: _Session) -> None:
    """What the call tells about the page now open: its URL and the snapshot refs point into."""
    if not call.succeeded or call.payload is None:
        return
    if call.tool in ("browser_navigate", "browser_snapshot"):
        snapshot = _text_field(call.payload, "snapshot")
        state.snapshot = snapshot[:MAX_SNAPSHOT_CHARS] if snapshot else None
    elif call.tool == "browser_back":
        state.snapshot = None  # the previous page's refs are gone
    url = _url(call.payload.get("url")) or _frame_url(call.payload)
    if url and call.tool in ("browser_navigate", "browser_snapshot", "browser_back"):
        state.page_url = url


def _frame_url(payload: Mapping[str, Any]) -> str | None:
    frames = payload.get("frame_tree")
    top = frames.get("top") if isinstance(frames, dict) else None
    return _url(top.get("url")) if isinstance(top, dict) else None


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
    event.update(
        attempt_id=attempt.attempt_id,
        source="user_correction",
        actor="human",
        action={"op": "other", "route": attempt.url},
        text=body,
    )
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


def _submit(home: Path, config: ActivityConfig, events: list[dict[str, Any]]) -> bool:
    """One batch through the receiver; ``True`` when it was acknowledged."""
    from . import _history_access as access
    from .ingest import StoreReceiver

    if config.collection_refusal is None:
        events = [_fit(event, config.max_event_bytes) for event in events]
    batch = {
        "schema_version": SCHEMA_VERSION,
        "producer_id": _PRODUCER_ID,
        "producer_kind": PRODUCER_KIND,
        "events": events,
    }
    receiver = StoreReceiver(home, config_loader=access.config, store_factory=_open)
    reply = receiver.ingest(principal(home), batch)
    if reply.get("type") != "activity_ack":
        _LOG.debug("mordred activity capture: batch refused (%s)", reply.get("reason"))
        return False
    return True


def _write(state: _Session, home: Path, config: ActivityConfig, events: list[dict[str, Any]]) -> bool:
    """Submit and time one write; slow writes count towards suspending the session. Never raises."""
    started = time.monotonic()
    try:
        return _submit(home, config, events)
    except Exception as exc:  # recording must never break the call or the turn
        _LOG.debug("mordred activity capture: write failed (%s)", type(exc).__name__)
        return False
    finally:
        _note_duration(state, home, time.monotonic() - started)


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
    task start needs the turn's message, so a call of a turn whose ``pre_llm_call`` was not seen gets none."""
    if state.episode is None or state.episode_turn != turn:
        state.episode, state.episode_turn, state.task_recorded = str(uuid.uuid4()), turn, False
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
    state = _session(access.session_key(session_id, task_id))
    with state.lock:
        if state.suspended:
            return
        call = _Call(
            tool_name,
            args if isinstance(args, Mapping) else {},
            _json_object(result),
            status if isinstance(status, str) else None,
            attempt_id(tool_call_id),
        )
        turn, turn_ref = _turn_of(state, turn_id)
        episode, pending = _episode_for(state, turn)
        refs = _refs(session_id, turn_ref)
        mapped = _MAPPERS.get(tool_name, _other)(call, state)
        events = [_task_start(state, episode, refs)] if pending else []
        events.append(_call_event(call, mapped, episode, refs))
        _observe(call, state)
        if _write(state, home, config, events):
            state.task_recorded = state.task_recorded or pending
            state.last = _Attempt(call.attempt_id, episode, mapped.route)


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


def _begin_turn(state: _Session, user_message: Any, turn_id: Any, platform: Any) -> None:
    hermes_turn = turn_id if isinstance(turn_id, str) and turn_id else None
    state.turn = hermes_turn or f"local-{next(_LOCAL_TURNS)}"
    state.turn_ref = _ref(hermes_turn)
    state.turn_at = time.time()
    state.human = not (isinstance(platform, str) and platform in NON_HUMAN_PLATFORMS)
    text = user_message.strip() if isinstance(user_message, str) else ""
    state.message = text[:MAX_TEXT_CHARS] or None
    state.message_cut = len(text) > MAX_TEXT_CHARS


def _record_turn(user_message: Any, session_id: Any, task_id: Any, turn_id: Any, platform: Any) -> None:
    from . import _history_access as access

    home = access.home()
    config = access.config(home)
    if not (_capturing(config) or _correcting(config)):
        return
    state = _session(access.session_key(session_id, task_id))
    with state.lock:
        _begin_turn(state, user_message, turn_id, platform)
        body = correction_text(user_message) if _correcting(config) and state.human else None
        if body is None or state.last is None or state.suspended:
            return
        _write(state, home, config, [_correction_event(state.last, body, _refs(session_id, state.turn_ref))])


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
