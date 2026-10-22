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
- UIDs are found with windowed ``UID SEARCH`` (bounded responses); a UID at or
  below the cursor (``UID n:*`` returns the last message) is filtered out.
- Groups of at most 200 UIDs: ``UID FETCH (UID RFC822.SIZE)`` first, so a
  message over 25 MiB is skipped and counted without downloading it; then
  batches of at most 64 MiB of literals, each fetched with ``BODY.PEEK[]``,
  planned by :func:`~.importer.plan_import` with the store-backed quote linker,
  written thread by thread under ONE ``import_runs`` row and published together
  with the cursor by :meth:`~..store.ImportStore.commit_batch`.
- The time budget (``budget_s``) is checked between batches; the socket
  timeout bounds a batch. Stopping early returns ``partial`` with the cursor at
  the last committed batch.

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
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Final

from .imap import ImapError, ImapSession
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
BATCH_BYTES: Final = 64 * 1024 * 1024
_FIRST_WINDOW: Final = 4096
_MAX_WINDOW: Final = 100_000
CURSOR_PREFIX: Final = "mail_imap"
_LOCK_NAME: Final = ".lock"
_MONTHS: Final = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

PARTIAL_REASONS: Final = frozenset({"time_budget", "max_messages", "error"})
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
_BOOL_FIELDS: Final = frozenset({"gmail", "cursor_reset", "partial", "dry_run"})
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
    """Forward (``uid``/``base``) or backfill (``low``) state of one mailbox in one ``UIDVALIDITY`` epoch."""

    mailbox_digest: str
    uidvalidity: int
    epoch: int
    role: str
    uid: int = 0
    base: int = 0
    low: int = 0

    def to_json(self) -> str:
        return json.dumps(
            {
                "base": self.base,
                "epoch": self.epoch,
                "low": self.low,
                "mailbox_digest": self.mailbox_digest,
                "role": self.role,
                "uid": self.uid,
                "uidvalidity": self.uidvalidity,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

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
        for name in ("uidvalidity", "epoch", "uid", "base", "low"):
            value = data.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None
            numbers.append(value)
        role = data.get("role")
        if role not in ("all", "inbox", "sent"):
            return None
        validity, epoch, uid, base, low = numbers
        return cls(digest, validity, epoch, str(role), uid, base, low)


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

    def __post_init__(self) -> None:
        if isinstance(self.max_messages, bool) or not 1 <= self.max_messages <= MAX_MAX_MESSAGES:
            raise ValueError("bad_max_messages")


@dataclass
class FetchEnv:
    """Every side effect of a fetch, injectable (tests replace them; :func:`default_env` builds production)."""

    home: Path
    secret_store: Any
    connect: Callable[[MailCredentials], ImapSession]
    open_store: Callable[[Path], Any]
    memory_guard: Callable[[Path], None]
    audit: Callable[[Mapping[str, Any]], None]
    platform: Callable[[], str] = field(default=lambda: sys.platform)
    clock: Callable[[], float] = time.monotonic
    now: Callable[[], float] = time.time
    lock: Callable[[Path], contextlib.AbstractContextManager[None]] = fetch_lock
    harden: Callable[[], None] = field(default=lambda: None)


def _default_connect(creds: MailCredentials) -> ImapSession:
    from .imap import connect

    return connect(creds.imap_host, creds.imap_port)


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


@dataclass
class _Run:
    """One fetch in progress (the gates have passed and the session is logged in)."""

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
        if self.env.clock() >= self.deadline:
            raise _Partial("time_budget")

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
            high = min(low + window - 1, top)
            criterion = f"{low}:*" if high >= top else f"{low}:{high}"
            found.update(uid for uid in self.session.search("UID", criterion) if after < uid <= top and uid >= low)
            low, window = high + 1, min(window * 2, _MAX_WINDOW)
        ordered = sorted(found)
        return ordered[:limit], len(ordered) > limit or (len(ordered) >= limit and low <= top)

    def older_than(self, below: int, limit: int, since: _dt.date | None) -> tuple[list[int], bool]:
        """Up to ``limit`` UIDs under ``below`` (matching ``SINCE``), newest first; whether more remain."""
        found: set[int] = set()
        high, window = below - 1, _FIRST_WINDOW
        extra = ("SINCE", imap_date(since)) if since is not None else ()
        while high >= 1 and len(found) <= limit:
            self.check_time()
            low = max(1, high - window + 1)
            found.update(uid for uid in self.session.search("UID", f"{low}:{high}", *extra) if low <= uid <= high)
            high, window = low - 1, min(window * 2, _MAX_WINDOW)
        ordered = sorted(found, reverse=True)
        return ordered[:limit], len(ordered) > limit or (len(ordered) >= limit and high >= 1)

    # -- batches ----------------------------------------------------------------------------

    def process(self, uids: Sequence[int], role: str, commit: Callable[[list[int]], Mapping[str, str]]) -> None:
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
                        self.batch(batch, covered, role, commit)
                        self.check_time()
                        batch, covered, batch_bytes = [], [], 0
                    batch.append(uid)
                    batch_bytes += size
                covered.append(uid)  # vanished and oversize UIDs are passed, never retried
            self.batch(batch, covered, role, commit)

    def batch(
        self, uids: list[int], covered: list[int], role: str, commit: Callable[[list[int]], Mapping[str, str]]
    ) -> None:
        if not covered:
            return
        fetched = self.session.fetch(uids, gmail=self.creds.gmail) if uids else []
        messages: list[tuple[bytes, TrustedMeta]] = []
        for item in fetched:
            if len(item.data) > MAX_MESSAGE_BYTES:
                self.result.skipped_oversize += 1  # the server under-reported its size
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

    def publish(self, messages: list[tuple[bytes, TrustedMeta]], updates: Mapping[str, str]) -> None:
        from .importer import plan_import
        from .store_link import StoreLinker

        linker = StoreLinker(self.store, self.creds.account)
        plan = plan_import([TrustedBytes(messages)], account=self.creds.account, own_addresses=self.own, linker=linker)
        if linker.error is not None:
            raise FetchStop("run_failed")  # never publish weaker attributions after a store failure
        skipped = sum(plan.report.skipped.values())
        self.result.skipped += skipped
        if self.options.dry_run:
            self.result.batches += 1  # planned, never written
            return
        counts: dict[str, int] = {"fetched": len(messages), "parsed": plan.report.parsed, "skipped": skipped}
        run_id = self.store.run_begin("mail")
        try:
            for thread in plan.threads:
                written = self.store.write_thread(
                    run_id, thread.messages, conversation=thread.conversation, merge_conversation=True
                )
                for key in ("inserted", "duplicates", "revised", "conflicts"):
                    counts[key] = counts.get(key, 0) + int(getattr(written, key))
            self.store.commit_batch(run_id, counts, updates)
        except BaseException as exc:
            with contextlib.suppress(Exception):
                self.store.run_fail(run_id, counts)
            if isinstance(exc, Exception):
                raise FetchStop("run_failed") from None
            raise
        self.result.batches += 1  # committed together with its cursor
        for key in ("inserted", "duplicates", "revised", "conflicts"):
            setattr(self.result, key, getattr(self.result, key) + counts.get(key, 0))

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
            self.backfill(role, key, digest, cursor)

    def forward(
        self, role: str, key: str, digest: str, status: Any, forward: Cursor | None, epoch: int, top: int
    ) -> Cursor | None:
        state: dict[str, Cursor | None] = {"cursor": forward}
        if forward is not None:
            uids, more = self.newer_than(forward.uid, top, self.remaining)
            base = forward.base
        else:
            uids, more = self.newest(top)
            base = uids[0] if uids else top + 1
            self.result.excluded_history += max(status.exists - len(uids), 0)
            if not uids:  # an empty mailbox: start the epoch at its top so the next run fetches forward
                fresh = Cursor(digest, status.uidvalidity, epoch, role, uid=top, base=base)
                if not self.options.dry_run:
                    self.store.set_meta(key, fresh.to_json())
                return fresh
        self.remaining -= len(uids)

        def commit(covered: list[int]) -> Mapping[str, str]:
            current = Cursor(digest, status.uidvalidity, epoch, role, uid=max(covered), base=base)
            state["cursor"] = current
            return {key: current.to_json()}

        self.process(uids, role, commit)
        if more:
            raise _Partial("max_messages")
        return state["cursor"]

    def newest(self, top: int) -> tuple[list[int], bool]:
        """The newest ``remaining`` UIDs at or below ``top``, oldest first (a first run never reports ``more``)."""
        if self.remaining <= 0:
            return [], False
        newest, _more = self.older_than(top + 1, self.remaining, None)
        return sorted(newest), False

    def backfill(self, role: str, key: str, digest: str, forward: Cursor) -> None:
        back_key = f"{key}.back"
        stored = Cursor.parse(self.store.get_meta(back_key), digest)
        if stored is not None and (stored.uidvalidity, stored.epoch) != (forward.uidvalidity, forward.epoch):
            stored = None
        below = forward.base if stored is None else min(stored.low, forward.base)
        if self.remaining <= 0 or below <= 1:
            return
        uids, more = self.older_than(below, self.remaining, self.options.since)
        self.remaining -= len(uids)

        def commit(covered: list[int]) -> Mapping[str, str]:
            low = min(covered)
            return {back_key: Cursor(digest, forward.uidvalidity, forward.epoch, role, low=low).to_json()}

        self.process(uids, role, commit)
        if more:
            raise _Partial("max_messages")


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
    session = env.connect(creds)
    try:
        session.login(creds.address, creds.app_password)
        deadline = env.clock() + options.budget_s
        run = _Run(store, session, creds, own, options, env, result, deadline, options.max_messages)
        try:
            for role in roles:
                run.check_time()
                run.mailbox(role)
        except _Partial as stop:
            result.partial, result.partial_reason = True, stop.reason
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
