"""IMAP mail sync: fetch new mail into ``mordred.db`` and report counts only.

One implementation for ``hermes-mordred mail fetch`` and the Hermes tool
``mordred_mail_sync`` (:func:`run_fetch`). Design record:
``docs/superpowers/specs/2026-10-22-mail-imap-sync-design.md``; SPEC
"IMAP sync (2026-10-22)".

Order of gates: macOS, sealed credentials present (flags only), memory
encryption armed, the ``mordred.db`` protection gate, the per-home fetch lock
(``sync_in_progress``), then ONE Enclave unseal and the IMAP login. A crashed
fetch's ``open`` mail runs are marked failed under the lock.

Per mailbox (Gmail: All Mail; other servers: INBOX, then the sent folder chosen at
``mail setup``):

- ``EXAMINE`` gives ``UIDVALIDITY``/``UIDNEXT``. The forward cursor
  (:data:`CURSOR_PREFIX` ``<account>.m<12 hex>``, JSON) holds the epoch, the
  highest committed UID and the ``base`` below which the forward path never
  fetched. A different ``UIDVALIDITY`` starts a new epoch (``cursor_reset``).
- First run of an epoch: the newest ``max_messages`` UIDs; older ones are
  counted as ``excluded_history`` and fetched only by ``--since`` (backfill,
  its own ``.back`` cursor, newest first, never moving the forward cursor).
  When the per-run cap is used up, a later mailbox's cursor is never moved
  without fetching: the run reports ``partial``/``max_messages`` instead.
- Backfill walks UIDs downward from the lowest one it covered, whatever the
  messages' dates; ``SINCE`` only filters. Its cursor records the day it
  covered (``since``); a later, wider ``--since`` first re-scans the covered
  range for the days it never asked for (``SINCE new BEFORE old``), then
  extends below it.
- UIDs are found with windowed ``UID SEARCH`` (bounded responses); a UID at or
  below the cursor (``UID n:*`` returns the last message) is filtered out.
- Groups of at most 200 UIDs: ``UID FETCH (UID RFC822.SIZE)`` first, so a
  message announced over 25 MiB is skipped and counted without downloading
  it; then batches of at most :data:`BATCH_BYTES` of announced sizes, each
  fetched with ``BODY.PEEK[]`` under the session's literal limits (a literal
  over 25 MiB is drained unread and counted, more than 64 MiB per response or
  a literal that does not fit aborts the connection: announced sizes are never
  trusted alone), planned by :func:`~.importer.plan_import` with the
  store-backed quote linker and the store's thread keys for referenced
  messages (so a reply chain split across batches stays one conversation),
  and written AND published in ONE transaction with the cursor and the
  conversation merge by :meth:`~..store.ImportStore.write_batch`, which also
  keeps every message's referenced ids and merges the conversations of
  replies fetched before their parent (C, then B, then A ends as one
  conversation).
- Deadlines: the session (:class:`~.imap.IoLimits`) refuses to start a command
  after ``budget_s`` and cuts an in-flight one at the hard deadline, connection
  establishment included (DNS, TCP, SOCKS5, TLS: a connection not open by then
  is ``imap_unreachable``); the run also checks between batches, and stops at a
  :class:`~.imap.CancelToken`.
  Stopping early returns ``partial`` with the cursor at the last committed
  batch; at most :data:`RUN_BYTES` of mail is read per run (``max_bytes``).

Output is :class:`FetchResult` only: integers, booleans and closed-enum codes.
No subject, name, address, label or body is returned, logged or audited.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import errno
import hashlib
import json
import os
import stat
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Final

from .imap import CancelToken, ImapError, ImapSession, ImapStopped, IoLimits
from .secrets import MailCredentials, MailSecretsError, ensure_private_dir, mail_dir
from .source import MAX_MESSAGE_BYTES, TrustedBytes, TrustedMeta

__all__ = [
    "CLI_BUDGET_S",
    "CURSOR_PREFIX",
    "DEFAULT_MAX_MESSAGES",
    "ERROR_CODES",
    "MAX_MAX_MESSAGES",
    "PARTIAL_REASONS",
    "TOOL_BUDGET_S",
    "Cursor",
    "FetchEnv",
    "FetchOptions",
    "FetchResult",
    "cursor_key",
    "default_env",
    "fetch_lock",
    "run_fetch",
]

DEFAULT_MAX_MESSAGES: Final = 2000
MAX_MAX_MESSAGES: Final = 2000
CLI_BUDGET_S: Final = 600.0
TOOL_BUDGET_S: Final = 60.0
GROUP_UIDS: Final = 200
#: Announced bytes planned per body fetch; the session refuses more than 64 MiB of actual literals.
BATCH_BYTES: Final = 48 * 1024 * 1024
#: Announced bytes fetched per run before it stops with ``partial_reason: max_bytes``.
RUN_BYTES: Final = 1024 * 1024 * 1024
_FIRST_WINDOW: Final = 4096
_MAX_WINDOW: Final = 100_000
CURSOR_PREFIX: Final = "mail_imap"
_LOCK_NAME: Final = ".lock"
_MONTHS: Final = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

PARTIAL_REASONS: Final = frozenset({"time_budget", "max_messages", "max_bytes", "cancelled", "error"})
#: Store-gate codes passed through as they are; every other store refusal is ``import_store_unavailable``.
_GATE_CODES: Final = frozenset({"not_armed", "conversion_pending", "unprotected_process", "no_key"})
ERROR_CODES: Final = frozenset(
    {
        "unsupported_platform",
        "mail_not_configured",
        "memory_encryption_required",
        "custody_busy",
        "import_store_unavailable",
        *_GATE_CODES,
        "sync_in_progress",
        "store_path_unsafe",
        "tee_unavailable",
        "tee_auth_cancelled",
        "secrets_corrupt",
        "routing_unavailable",
        "egress_unsupported",
        "imap_unreachable",
        "imap_auth_failed",
        "imap_protocol",
        "imap_command_refused",
        "run_failed",
        "invalid_request",
        "fetch_failed",
    }
)


class FetchStop(Exception):
    """Ends a fetch with a content-free ``code`` (an :data:`ERROR_CODES` member)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if code in ERROR_CODES else "fetch_failed"


class _Partial(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- result ---------------------------------------------------------------------------------------


@dataclass
class FetchResult:
    """The only output of a fetch: counts, flags and closed-enum codes (see :meth:`as_dict`)."""

    inserted: int = 0
    duplicates: int = 0
    revised: int = 0
    conflicts: int = 0
    fetched: int = 0
    skipped: int = 0
    skipped_oversize: int = 0
    batches: int = 0
    mailboxes: int = 0
    excluded_history: int = 0
    gmail: bool = False
    cursor_reset: bool = False
    partial: bool = False
    dry_run: bool = False
    #: Set by the Hermes tool only: its worker did not end within the call's bound, so it was cancelled and
    #: left behind (a daemon thread that stops at its next check); the counts are then unknown and reported as 0.
    abandoned: bool = False
    partial_reason: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, int | bool | str | None]:
        """Every field, type- and enum-checked (a bad value raises; nothing else can appear)."""
        return checked_result({item.name: getattr(self, item.name) for item in fields(self)})


_INT_FIELDS: Final = frozenset(
    {
        "inserted",
        "duplicates",
        "revised",
        "conflicts",
        "fetched",
        "skipped",
        "skipped_oversize",
        "batches",
        "mailboxes",
        "excluded_history",
    }
)
_BOOL_FIELDS: Final = frozenset({"gmail", "cursor_reset", "partial", "dry_run", "abandoned"})
RESULT_FIELDS: Final = _INT_FIELDS | _BOOL_FIELDS | {"partial_reason", "error"}


def checked_result(data: Mapping[str, object]) -> dict[str, int | bool | str | None]:
    """The fixed serializer: exactly :data:`RESULT_FIELDS`, each of its type; anything else raises ``ValueError``."""
    if set(data) != RESULT_FIELDS:
        raise ValueError("result_fields")
    out: dict[str, int | bool | str | None] = {}
    for key in sorted(data):
        out[key] = _checked_value(key, data[key])
    return out


def _checked_value(key: str, value: object) -> int | bool | str | None:
    if key in _INT_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("result_value")
        return value
    if key in _BOOL_FIELDS:
        if not isinstance(value, bool):
            raise ValueError("result_value")
        return value
    allowed = PARTIAL_REASONS if key == "partial_reason" else ERROR_CODES
    if value is None:
        return None
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("result_value")
    return value


# --- cursors --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Cursor:
    """Forward (``uid``/``base``) or backfill (``low``) state of one mailbox in one ``UIDVALIDITY`` epoch.

    Backfill: every UID in ``[low, base)`` whose server date is on or after the day
    ``since`` (a proleptic Gregorian ordinal; 0 = unknown) has been fetched or
    skipped. ``wsince``/``whigh`` record a wider ``--since`` in progress: the UIDs
    in ``[whigh, base)`` were re-scanned for the days ``[wsince, since)``.
    """

    mailbox_digest: str
    uidvalidity: int
    epoch: int
    role: str
    uid: int = 0
    base: int = 0
    low: int = 0
    since: int = 0
    wsince: int = 0
    whigh: int = 0

    def to_json(self) -> str:
        data: dict[str, object] = {
            "base": self.base,
            "epoch": self.epoch,
            "low": self.low,
            "mailbox_digest": self.mailbox_digest,
            "role": self.role,
            "uid": self.uid,
            "uidvalidity": self.uidvalidity,
        }
        for name in _OPTIONAL_NUMBERS:  # backfill only; omitted when 0 so a value stays within 256 characters
            if getattr(self, name):
                data[name] = getattr(self, name)
        return json.dumps(data, separators=(",", ":"), sort_keys=True)

    @classmethod
    def parse(cls, raw: str | None, digest: str) -> Cursor | None:
        """A stored cursor for ``digest``; a missing, foreign or malformed value is ``None``."""
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get("mailbox_digest") != digest:
            return None
        numbers: list[int] = []
        for name in ("uidvalidity", "epoch", "uid", "base", "low", *_OPTIONAL_NUMBERS):
            value = data.get(name, 0 if name in _OPTIONAL_NUMBERS else None)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None
            numbers.append(value)
        role = data.get("role")
        if role not in ("all", "inbox", "sent"):
            return None
        validity, epoch, uid, base, low, since, wsince, whigh = numbers
        if max(since, wsince) > _MAX_DAY:
            return None  # not a day this module wrote
        return cls(digest, validity, epoch, str(role), uid, base, low, since, wsince, whigh)


_OPTIONAL_NUMBERS: Final = ("since", "wsince", "whigh")
_MAX_DAY: Final = _dt.date.max.toordinal()


def mailbox_digest(creds: MailCredentials, name: str) -> str:
    """Identifies one mailbox of one account on one server (never stored in clear)."""
    seed = f"{creds.imap_host.lower()}\n{creds.imap_port}\n{creds.address.lower()}\n{name}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def cursor_key(account: str, digest: str) -> str:
    """``mail_imap.<account>.m<12 hex>`` (the store's key grammar: lowercase components, a letter first)."""
    return f"{CURSOR_PREFIX}.{account}.m{digest[:12]}"


def last_fetch_key(account: str) -> str:
    return f"{CURSOR_PREFIX}.{account}.last"


def imap_date(day: _dt.date) -> str:
    """``SINCE`` date (``1-Feb-2026``), independent of the process locale."""
    return f"{day.day}-{_MONTHS[day.month - 1]}-{day.year}"


# --- lock -----------------------------------------------------------------------------------------


@contextlib.contextmanager
def fetch_lock(home: Path) -> Iterator[None]:
    """The per-home mail writer lock (``<home>/mordred/mail/.lock``); held elsewhere → ``sync_in_progress``."""
    if sys.platform == "win32":  # no mordred.db on Windows: nothing to serialize
        yield
        return
    import fcntl  # POSIX only

    try:
        directory = ensure_private_dir(mail_dir(home))
    except (MailSecretsError, OSError):
        raise FetchStop("store_path_unsafe") from None
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(directory / _LOCK_NAME, flags, 0o600)
    except OSError:
        raise FetchStop("store_path_unsafe") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise FetchStop("store_path_unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise FetchStop("sync_in_progress") from None
            raise FetchStop("store_path_unsafe") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# --- environment ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class FetchOptions:
    max_messages: int = DEFAULT_MAX_MESSAGES
    roles: tuple[str, ...] | None = None  # restrict to these configured roles (``--mailbox``)
    since: _dt.date | None = None
    dry_run: bool = False
    budget_s: float = CLI_BUDGET_S
    via: str = "cli"
    #: Set from another thread to stop the fetch (the tool's worker on a cancelled call).
    cancel: CancelToken | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.max_messages, bool) or not 1 <= self.max_messages <= MAX_MAX_MESSAGES:
            raise ValueError("bad_max_messages")


@dataclass
class FetchEnv:
    """Every side effect of a fetch, injectable (tests replace them; :func:`default_env` builds production)."""

    home: Path
    secret_store: Any
    connect: Callable[[MailCredentials, IoLimits], ImapSession]
    open_store: Callable[[Path], Any]
    memory_guard: Callable[[Path], None]
    audit: Callable[[Mapping[str, Any]], None]
    platform: Callable[[], str] = field(default=lambda: sys.platform)
    clock: Callable[[], float] = time.monotonic
    now: Callable[[], float] = time.time
    lock: Callable[[Path], contextlib.AbstractContextManager[None]] = fetch_lock
    harden: Callable[[], None] = field(default=lambda: None)


def _default_connect(creds: MailCredentials, limits: IoLimits) -> ImapSession:
    from .imap import connect

    return connect(creds.imap_host, creds.imap_port, limits=limits)


def _default_open_store(home: Path) -> Any:
    from .. import store as store_module

    return store_module.open_import_store(home)


def _default_memory_guard(home: Path) -> None:
    from ...extension.telegram.memory_guard import require_memory_encryption

    require_memory_encryption(home)


def _default_audit(entry: Mapping[str, Any]) -> None:
    from .._audit import append

    append(entry)


def _default_harden() -> None:
    from ...extension.telegram.hardening import harden_process

    harden_process()


def default_env(home: Path | None = None) -> FetchEnv:
    from ..._home import hermes_home
    from .secrets import MailSecretStore

    return FetchEnv(
        home=home if home is not None else hermes_home(),
        secret_store=MailSecretStore(),
        connect=_default_connect,
        open_store=_default_open_store,
        memory_guard=_default_memory_guard,
        audit=_default_audit,
        harden=_default_harden,
    )


# --- the fetch ------------------------------------------------------------------------------------


def _code(exc: BaseException, fallback: str) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code in ERROR_CODES else fallback


def _store_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    return code if code in _GATE_CODES else "import_store_unavailable"


def _chunks(items: Sequence[int], size: int) -> Iterator[list[int]]:
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


Commit = Callable[[list[int]], Mapping[str, str]]


@dataclass
class _Run:
    """One fetch in progress (the gates have passed and the session is open)."""

    store: Any
    session: ImapSession
    creds: MailCredentials
    own: tuple[str, ...]
    options: FetchOptions
    env: FetchEnv
    result: FetchResult
    deadline: float
    remaining: int

    # -- budget -----------------------------------------------------------------------------

    def check_time(self) -> None:
        cancel = self.options.cancel
        if cancel is not None and cancel.cancelled:
            raise _Partial("cancelled")
        if self.env.clock() >= self.deadline:
            raise _Partial("time_budget")

    def save(self, key: str, cursor: Cursor) -> None:
        """A cursor move that publishes no row (nothing new below it, or an empty mailbox)."""
        if not self.options.dry_run:
            self.store.set_meta(key, cursor.to_json())

    # -- UID discovery ----------------------------------------------------------------------

    def top_uid(self, uidnext: int | None, exists: int) -> int:
        if exists <= 0:
            return 0 if uidnext is None else max(uidnext - 1, 0)
        if uidnext is not None and uidnext > 1:
            return uidnext - 1
        found = self.session.search("UID", "*")
        return max(found) if found else 0

    def newer_than(self, after: int, top: int, limit: int) -> tuple[list[int], bool]:
        """Up to ``limit`` UIDs in ``(after, top]``, oldest first; whether more remain."""
        found: set[int] = set()
        low, window = after + 1, _FIRST_WINDOW
        while low <= top and len(found) <= limit:
            self.check_time()
            high = min(low + window - 1, top)
            criterion = f"{low}:*" if high >= top else f"{low}:{high}"
            found.update(uid for uid in self.session.search("UID", criterion) if after < uid <= top and uid >= low)
            low, window = high + 1, min(window * 2, _MAX_WINDOW)
        ordered = sorted(found)
        return ordered[:limit], len(ordered) > limit or (len(ordered) >= limit and low <= top)

    def walk_down(self, below: int, floor: int, limit: int, criteria: Sequence[str] = ()) -> tuple[list[int], bool]:
        """Up to ``limit`` UIDs in ``[floor, below)`` matching ``criteria``, newest first; whether more remain."""
        found: set[int] = set()
        high, window = below - 1, _FIRST_WINDOW
        while high >= floor and len(found) <= limit:
            self.check_time()
            low = max(floor, high - window + 1)
            found.update(uid for uid in self.session.search("UID", f"{low}:{high}", *criteria) if low <= uid <= high)
            high, window = low - 1, min(window * 2, _MAX_WINDOW)
        ordered = sorted(found, reverse=True)
        return ordered[:limit], len(ordered) > limit or (len(ordered) >= limit and high >= floor)

    # -- batches ----------------------------------------------------------------------------

    def process(self, uids: Sequence[int], role: str, commit: Commit) -> None:
        """Size-check, fetch, plan and publish ``uids`` in order; ``commit(covered)`` gives the cursor updates."""
        for group in _chunks(uids, GROUP_UIDS):
            self.check_time()
            sizes = self.session.sizes(group)
            batch: list[int] = []
            covered: list[int] = []
            batch_bytes = 0
            for uid in group:
                size = sizes.get(uid)
                if size is not None and size > MAX_MESSAGE_BYTES:
                    self.result.skipped_oversize += 1
                elif size is not None:
                    if batch and batch_bytes + size > BATCH_BYTES:
                        self.batch(batch, covered, role, commit, batch_bytes)
                        batch, covered, batch_bytes = [], [], 0
                    batch.append(uid)
                    batch_bytes += size
                covered.append(uid)  # vanished and oversize UIDs are passed, never retried
            self.batch(batch, covered, role, commit, batch_bytes)

    def batch(self, uids: list[int], covered: list[int], role: str, commit: Commit, announced: int) -> None:
        if not covered:
            return
        self.check_time()
        if uids and self.session.bytes_read + announced > RUN_BYTES:
            raise _Partial("max_bytes")
        fetched = self.session.fetch(uids, gmail=self.creds.gmail) if uids else []
        messages: list[tuple[bytes, TrustedMeta]] = []
        for item in fetched:
            if item.oversize or len(item.data) > MAX_MESSAGE_BYTES:
                self.result.skipped_oversize += 1  # the server under-reported its size: drained unread
                continue
            labels = item.labels if self.creds.gmail else ()
            messages.append((item.data, TrustedMeta(labels=labels, thread_id=item.thread_id, folder_role=role)))
        self.result.fetched += len(messages)
        updates = commit(covered)
        if not messages:
            if not self.options.dry_run:
                for key, value in updates.items():
                    self.store.set_meta(key, value)
            return
        self.publish(messages, updates)

    def stored_threads(self, message_ids: Sequence[str]) -> dict[str, str]:
        """Message id → thread key of this account's committed messages (cross-batch threading)."""
        try:
            found = self.store.find_messages("mail", self.creds.account, message_ids=message_ids)
        except Exception:
            raise FetchStop("run_failed") from None
        return {item.message.message_id: item.conversation.conversation_id for item in found}

    def publish(self, messages: list[tuple[bytes, TrustedMeta]], updates: Mapping[str, str]) -> None:
        from .importer import plan_import
        from .store_link import StoreLinker

        linker = StoreLinker(self.store, self.creds.account)
        plan = plan_import(
            [TrustedBytes(messages)],
            account=self.creds.account,
            own_addresses=self.own,
            linker=linker,
            thread_resolver=self.stored_threads,
        )
        if linker.error is not None:
            raise FetchStop("run_failed")  # never publish weaker attributions after a store failure
        skipped = sum(plan.report.skipped.values())
        self.result.skipped += skipped
        if self.options.dry_run:
            self.result.batches += 1  # planned, never written
            return
        counts: dict[str, int] = {"fetched": len(messages), "parsed": plan.report.parsed, "skipped": skipped}
        try:
            run_id = self.store.run_begin("mail")
        except Exception:
            raise FetchStop("run_failed") from None
        try:
            written = self.store.write_batch(
                run_id,
                [thread.messages for thread in plan.threads],
                conversations=[thread.conversation for thread in plan.threads],
                counts=counts,
                meta_updates=updates,
                refs=plan.refs,
            )
        except BaseException as exc:
            with contextlib.suppress(Exception):
                self.store.run_fail(run_id, counts)  # nothing of the batch is visible: it was rolled back
            if isinstance(exc, Exception):
                raise FetchStop("run_failed") from None
            raise
        self.result.batches += 1  # committed together with its cursor
        for key in ("inserted", "duplicates", "revised", "conflicts"):
            setattr(self.result, key, getattr(self.result, key) + int(getattr(written, key)))

    # -- mailboxes --------------------------------------------------------------------------

    def mailbox(self, role: str) -> None:
        name = self.creds.mailboxes[role]
        status = self.session.examine(name)
        self.result.mailboxes += 1
        digest = mailbox_digest(self.creds, name)
        key = cursor_key(self.creds.account, digest)
        stored = Cursor.parse(self.store.get_meta(key), digest)
        epoch = 0 if stored is None else stored.epoch
        forward = stored
        if stored is not None and stored.uidvalidity != status.uidvalidity:
            forward, epoch = None, stored.epoch + 1
            self.result.cursor_reset = True
        top = self.top_uid(status.uidnext, status.exists)
        cursor = self.forward(role, key, digest, status, forward, epoch, top)
        if self.options.since is not None and cursor is not None:
            self.backfill(key, digest, cursor, self.options.since.toordinal())

    def forward(
        self, role: str, key: str, digest: str, status: Any, forward: Cursor | None, epoch: int, top: int
    ) -> Cursor | None:
        if forward is None and status.exists <= 0:  # an empty mailbox: start the epoch at its top
            fresh = Cursor(digest, status.uidvalidity, epoch, role, uid=top, base=top + 1)
            self.save(key, fresh)
            return fresh
        if self.remaining <= 0:
            if forward is None or top > forward.uid:
                raise _Partial("max_messages")  # never move a cursor past mail this run did not fetch
            return forward
        if forward is not None:
            uids, more = self.newer_than(forward.uid, top, self.remaining)
            base = forward.base
        else:
            uids, more = self.newest(top), False
            if not uids:
                return None  # the server lists mail but SEARCH finds none: leave the cursor unset
            base = uids[0]
            self.result.excluded_history += max(status.exists - len(uids), 0)
        self.remaining -= len(uids)
        state: dict[str, Cursor | None] = {"cursor": forward}

        def commit(covered: list[int]) -> Mapping[str, str]:
            current = Cursor(digest, status.uidvalidity, epoch, role, uid=max(covered), base=base)
            state["cursor"] = current
            return {key: current.to_json()}

        self.process(uids, role, commit)
        if more:
            raise _Partial("max_messages")
        return state["cursor"]

    def newest(self, top: int) -> list[int]:
        """The newest ``remaining`` UIDs at or below ``top``, oldest first (a first run never reports ``more``)."""
        newest, _more = self.walk_down(top + 1, 1, self.remaining)
        return sorted(newest)

    # -- backfill ---------------------------------------------------------------------------

    def backfill(self, key: str, digest: str, forward: Cursor, target: int) -> None:
        """``--since``: widen the covered range to ``target`` if needed, then extend it downward."""
        back_key = f"{key}.back"
        state = Cursor.parse(self.store.get_meta(back_key), digest)
        epoch = (forward.uidvalidity, forward.epoch)
        if state is None or (state.uidvalidity, state.epoch) != epoch or state.low >= forward.base:
            state = Cursor(digest, forward.uidvalidity, forward.epoch, forward.role, low=forward.base, since=target)
        if state.since == 0 or target < state.since:
            state = self.widen(back_key, state, target, forward.base)
        self.extend(back_key, state, target)

    def widen(self, back_key: str, state: Cursor, target: int, base: int) -> Cursor:
        """Re-scan the covered ``[low, base)`` for the days ``[target, since)`` an earlier run never asked for."""
        if state.wsince != target or not state.low <= state.whigh <= base:
            state = replace(state, wsince=target, whigh=base)
        criteria: tuple[str, ...] = ("SINCE", imap_date(_dt.date.fromordinal(target)))
        if state.since:
            criteria += ("BEFORE", imap_date(_dt.date.fromordinal(state.since)))
        uids, more = self.walk_down(state.whigh, state.low, self.remaining, criteria)
        self.remaining -= len(uids)
        current = {"state": state}

        def commit(covered: list[int]) -> Mapping[str, str]:
            current["state"] = replace(current["state"], whigh=min(covered))
            return {back_key: current["state"].to_json()}

        self.process(uids, state.role, commit)
        if more:
            raise _Partial("max_messages")
        done = replace(current["state"], since=target, wsince=0, whigh=0)
        self.save(back_key, done)
        return done

    def extend(self, back_key: str, state: Cursor, target: int) -> None:
        """Walk below ``low`` by UID, whatever the dates: every UID dated on or after ``target``."""
        covers = max(state.since, target)  # a narrower request makes the record claim less, never more
        criteria = ("SINCE", imap_date(_dt.date.fromordinal(target)))
        uids, more = self.walk_down(state.low, 1, self.remaining, criteria)
        self.remaining -= len(uids)
        current = {"state": state}

        def commit(covered: list[int]) -> Mapping[str, str]:
            current["state"] = replace(current["state"], low=min(covered), since=covers)
            return {back_key: current["state"].to_json()}

        self.process(uids, state.role, commit)
        if more:
            raise _Partial("max_messages")
        done = replace(current["state"], low=1, since=covers)
        if done != state:
            self.save(back_key, done)


def _roles(creds: MailCredentials, options: FetchOptions) -> tuple[str, ...]:
    roles = tuple(role for role in creds.roles if options.roles is None or role in options.roles)
    if not roles:
        raise FetchStop("invalid_request")
    return roles


def _sync(store: Any, creds: MailCredentials, options: FetchOptions, env: FetchEnv, result: FetchResult) -> None:
    from .store_link import remember_own_addresses, stored_own_addresses

    roles = _roles(creds, options)
    result.gmail = creds.gmail
    try:
        own = tuple(sorted(set(creds.own_addresses) | stored_own_addresses(store, creds.account)))
        if not options.dry_run:
            remember_own_addresses(store, creds.account, creds.own_addresses)
    except Exception as exc:
        raise FetchStop(_store_code(exc)) from None
    limits = IoLimits.for_budget(options.budget_s, clock=env.clock, cancel=options.cancel)
    try:
        session = env.connect(creds, limits)
    except ImapStopped as stop:
        result.partial, result.partial_reason = True, stop.reason
        return
    try:
        run = _Run(store, session, creds, own, options, env, result, limits.deadline, options.max_messages)
        try:
            session.login(creds.address, creds.app_password)
            for role in roles:
                run.check_time()
                run.mailbox(role)
        except _Partial as stop:
            result.partial, result.partial_reason = True, stop.reason
        except ImapStopped as stopped:  # the session's deadline or a cancellation, inside a command
            result.partial, result.partial_reason = True, stopped.reason
    finally:
        session.logout()


def _gated_store(options: FetchOptions, env: FetchEnv) -> Any:
    if env.platform() != "darwin":
        raise FetchStop("unsupported_platform")
    if env.secret_store.flags() is None:
        raise FetchStop("mail_not_configured")
    try:
        env.memory_guard(env.home)
    except Exception as exc:
        raise FetchStop(_code(exc, "memory_encryption_required")) from None
    try:
        return env.open_store(env.home)
    except Exception as exc:
        raise FetchStop(_store_code(exc)) from None


def _unseal(env: FetchEnv) -> MailCredentials:
    env.harden()
    try:
        creds = env.secret_store.load()
    except Exception as exc:
        raise FetchStop(_code(exc, "secrets_corrupt")) from None
    if not isinstance(creds, MailCredentials):
        raise FetchStop("mail_not_configured")
    return creds


def _locked_fetch(store: Any, options: FetchOptions, env: FetchEnv, result: FetchResult) -> None:
    if not options.dry_run:
        try:
            store.fail_open_runs("mail")
        except Exception as exc:
            raise FetchStop(_store_code(exc)) from None
    creds = _unseal(env)
    try:
        _sync(store, creds, options, env, result)
    finally:
        del creds
    if not options.dry_run:
        with contextlib.suppress(Exception):
            store.set_meta(last_fetch_key(_account_of(env)), _last_json(result, env))


def _account_of(env: FetchEnv) -> str:
    flags = env.secret_store.flags() or {}
    return str(flags.get("account", "mail"))


def _last_json(result: FetchResult, env: FetchEnv) -> str:
    return json.dumps(
        {"at": int(env.now()), "error": result.error, "partial": result.partial, "gmail": result.gmail},
        separators=(",", ":"),
        sort_keys=True,
    )


def _audit(env: FetchEnv, options: FetchOptions, result: FetchResult) -> None:
    if options.dry_run:
        return
    decision = "failed" if result.error else ("partial" if result.partial else "committed")
    entry: dict[str, Any] = {"event": "mail.fetch", "decision": decision, "reason": None, "via": options.via}
    entry.update(result.as_dict())
    with contextlib.suppress(Exception):
        env.audit(entry)


def run_fetch(options: FetchOptions, env: FetchEnv | None = None) -> FetchResult:
    """Fetch new mail into ``mordred.db``; never raises for a refusal (the code is ``result.error``)."""
    env = env if env is not None else default_env()
    result = FetchResult(dry_run=options.dry_run)
    try:
        store = _gated_store(options, env)
        lock = contextlib.nullcontext() if options.dry_run else env.lock(env.home)
        with lock:
            _locked_fetch(store, options, env, result)
    except FetchStop as stop:
        result.error = stop.code
    except ImapStopped as stopped:
        result.partial, result.partial_reason = True, stopped.reason
    except ImapError as exc:
        result.error = _code(exc, "imap_protocol")
    except MailSecretsError as exc:
        result.error = _code(exc, "secrets_corrupt")
    except Exception:  # never stringified: the class name is not even kept
        result.error = "fetch_failed"
    if result.error is not None and result.batches:
        result.partial, result.partial_reason = True, "error"
    _audit(env, options, result)
    return result
