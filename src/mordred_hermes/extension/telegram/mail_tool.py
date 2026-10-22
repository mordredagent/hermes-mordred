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
- **Budget**: about 60 seconds of fetching, checked between batches; the result
  then says ``partial: true`` with ``partial_reason: "time_budget"`` and the
  cursor already holds the committed progress, so the next call continues. The
  fetch runs in a worker thread that has finished before the result returns.
- **Reader mode**: not a reader tool (nothing private is returned), allowed in a
  reader session and never a taint source (``privacy_check.egress.MAIL_SYNC_TOOL``).
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Final

TOOL_NAME: Final = "mordred_mail_sync"
_MAX: Final = 2000
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


def _fetch(max_messages: int) -> dict[str, Any]:
    from ...imports.mail.imap_sync import TOOL_BUDGET_S, FetchOptions, default_env, run_fetch

    options = FetchOptions(max_messages=max_messages, budget_s=TOOL_BUDGET_S, via="tool")
    return dict(run_fetch(options, default_env()).as_dict())


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
    result = await asyncio.to_thread(_fetch, max_messages)  # awaited: the worker is done before we return
    return json.dumps({**result, "note": NOTE})
