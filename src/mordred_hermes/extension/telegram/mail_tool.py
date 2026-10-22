"""Hermes tool ``mordred_mail_sync``: fetch the owner's new mail into ``mordred.db``; counts only.

The owner says "sync my mail" in a Hermes chat; the model calls this tool; Mordred
unseals the IMAP credentials (Secure Enclave), fetches new mail read-only and
writes it through the mail collector (:func:`mordred_hermes.imports.mail.imap_sync.run_fetch`,
the same function as ``hermes-mordred mail fetch``). Hermes receives only the
fixed counts-only result: no subject, name, address, label or body ever enters
the conversation, ``state.db`` or a log.

- **Arguments**: ``max_messages`` (integer 1-2000) only; anything else —
  another key, a boolean, a float, a string — is ``invalid_request``. The model
  cannot choose the account, the server or the mailbox.
- **Visibility** (``check_fn``, offline): macOS, the ``mordred.db`` gate passes,
  mail credentials are sealed, and the Hermes model is Venice or loopback (the
  rule of the other Mordred tools).
- **Every call** repeats the gates: the running model's endpoint (a Venice model
  must be ``private`` in the live catalog), then inside the fetch the platform,
  the sealed credentials, memory encryption, the store gate and the fetch lock.
- **Budget**: about 60 seconds: no IMAP command starts after it, an in-flight
  one (connection establishment included: DNS, TCP, SOCKS5, TLS) is cut at most
  30 seconds later (the session's watchdog shuts the socket down, so a server
  trickling bytes cannot extend it); the result then says ``partial: true``
  with ``partial_reason: "time_budget"`` and the cursor already holds the
  committed progress, so the next call continues.
- **Worker**: the fetch runs in one named daemon thread (:data:`WORKER_NAME`).
  The handler normally returns only after that thread has ended. A cancelled
  call sets the fetch's :class:`CancelToken` (which shuts the IMAP socket down
  at once and wakes a resolver wait), then waits for the worker at most the
  remaining budget plus :data:`CANCEL_GRACE_S` (repeated cancellations are
  absorbed only until then) and re-raises. A worker still running after the
  budget plus :data:`ABANDON_GRACE_S` (something the session's bounds cannot
  interrupt) is cancelled and abandoned: the call returns ``partial: true``,
  ``partial_reason: "cancelled"`` and ``abandoned: true`` with zero counts.
  An abandoned worker stops at its next check (a batch already being written
  still commits atomically with its cursor), so the next call continues.
- **Reader mode**: not a reader tool (nothing private is returned), allowed in a
  reader session and never a taint source (``privacy_check.egress.MAIL_SYNC_TOOL``).
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from ...imports.mail.imap import CancelToken

TOOL_NAME: Final = "mordred_mail_sync"
WORKER_NAME: Final = "mordred-mail-sync"
_MAX: Final = 2000
_POLL_S: Final = 0.05
#: After a cancellation the worker is waited for until the budget's end plus this (the session's hard grace).
CANCEL_GRACE_S: Final = 30.0
#: Without a cancellation the worker is waited for until the budget's end plus this: the session's hard
#: grace (30 s), its polite LOGOUT (5 s) and a margin. A worker still running then is abandoned.
ABANDON_GRACE_S: Final = 40.0
NOTE: Final = (
    "Mordred fetched the user's new mail into its encrypted store; only counts are reported here. "
    "partial=true means more remains: call this tool again to continue. To read or quote messages use "
    "mordred_history_search. error=mail_not_configured means the user must run `hermes-mordred mail setup` "
    "in a terminal (never ask for the address or password in the chat)."
)

SCHEMA: Final[dict[str, Any]] = {
    "name": TOOL_NAME,
    "description": (
        "Fetch the user's new e-mail into Mordred's encrypted history store (read-only on the mail server; "
        "nothing is marked read, moved or sent). Call it when the user asks to sync, refresh or import their "
        "mail. Returns counts only (inserted, duplicates, partial, error...), never message content; afterwards "
        "use mordred_history_search to read mail. Each call may ask the user for Touch ID."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "max_messages": {
                "type": "integer",
                "minimum": 1,
                "maximum": _MAX,
                "description": "Optional cap on messages fetched in this call (1-2000, default 2000).",
            },
        },
        "additionalProperties": False,
    },
}


class _Invalid(Exception):
    pass


def parse_args(args: object) -> int:
    """The validated ``max_messages`` (default 2000); anything else raises."""
    if args is None:
        return _MAX
    if not isinstance(args, dict) or set(args) - {"max_messages"}:
        raise _Invalid()
    value = args.get("max_messages", _MAX)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX:
        raise _Invalid()
    return value


def _platform() -> str:
    return sys.platform


def _mail_configured() -> bool:
    try:
        from ...imports.mail.secrets import MailSecretStore

        return MailSecretStore().flags() is not None
    except Exception:
        return False


def mail_sync_available() -> bool:
    """check_fn: macOS, a Venice/loopback Hermes model, the store gate, and sealed mail credentials."""
    from .hermes_tools import _classify_endpoint, _configured_model, _store_gate_open

    if _platform() != "darwin":
        return False
    _model, base_url = _configured_model()
    if _classify_endpoint(base_url) is None:
        return False
    return _store_gate_open() and _mail_configured()


def _fetch(max_messages: int, cancel: CancelToken | None = None) -> dict[str, Any]:
    from ...imports.mail import imap_sync

    options = imap_sync.FetchOptions(
        max_messages=max_messages, budget_s=imap_sync.TOOL_BUDGET_S, via="tool", cancel=cancel
    )
    return dict(imap_sync.run_fetch(options, imap_sync.default_env()).as_dict())


def _left(until: float) -> float:
    return until - time.monotonic()


async def _joined(worker: threading.Thread, until: float) -> bool:
    """Wait for ``worker`` until the monotonic time ``until`` without blocking the event loop; True if it ended."""
    while worker.is_alive() and _left(until) > 0:
        await asyncio.sleep(min(_POLL_S, max(_left(until), 0.0)))
    if worker.is_alive():
        return False
    worker.join()
    return True


async def _joined_after_cancel(worker: threading.Thread, until: float) -> bool:
    """:func:`_joined` that absorbs further cancellations, but never past ``until``."""
    while worker.is_alive() and _left(until) > 0:
        try:
            await asyncio.sleep(min(_POLL_S, max(_left(until), 0.0)))
        except asyncio.CancelledError:
            continue  # the wait is bounded: the caller re-raises at ``until`` at the latest
    if worker.is_alive():
        return False
    worker.join()
    return True


def _abandoned() -> dict[str, Any]:
    from ...imports.mail.imap_sync import FetchResult

    return dict(FetchResult(partial=True, partial_reason="cancelled", abandoned=True).as_dict())


async def _run_worker(max_messages: int) -> dict[str, Any] | None:
    """The fetch in a named worker thread; every wait for it is bounded (see the module docstring)."""
    from ...imports.mail import imap_sync
    from ...imports.mail.imap import CancelToken

    cancel = CancelToken()
    box: dict[str, dict[str, Any]] = {}

    def target() -> None:
        try:
            box["result"] = _fetch(max_messages, cancel)
        except Exception:  # never stringified; the handler reports fetch_failed
            box.pop("result", None)

    worker = threading.Thread(target=target, name=WORKER_NAME, daemon=True)
    budget_end = time.monotonic() + imap_sync.TOOL_BUDGET_S
    worker.start()
    try:
        ended = await _joined(worker, budget_end + ABANDON_GRACE_S)
    except asyncio.CancelledError:
        cancel.cancel()  # the fetch stops at once: its IMAP socket is shut down, a resolver wait woken
        await _joined_after_cancel(worker, max(budget_end, time.monotonic()) + CANCEL_GRACE_S)
        raise  # an abandoned worker is a daemon that has been told to stop
    if not ended:
        cancel.cancel()
        return _abandoned()
    return box.get("result")


def _error(code: str) -> str:
    return json.dumps({"error": code, "note": NOTE})


async def mordred_mail_sync(
    args: dict[str, Any], parent_agent: Any = None, session_id: str | None = None, **_: Any
) -> str:
    """Fetch new mail; returns the counts-only result (``session_id`` is accepted and unused)."""
    del session_id
    try:
        max_messages = parse_args(args)
    except _Invalid:
        return _error("invalid_request")
    from .hermes_tools import _require_reader_allowed

    try:
        await _require_reader_allowed(parent_agent)
    except Exception as exc:
        code = getattr(exc, "code", None)
        allowed = {"hermes_model_not_allowed", "hermes_model_not_private", "routing_unavailable"}
        return _error(code if code in allowed else "fetch_failed")
    result = await _run_worker(max_messages)  # the worker has ended, or was abandoned (``abandoned: true``)
    if result is None:
        return _error("fetch_failed")
    return json.dumps({**result, "note": NOTE})
