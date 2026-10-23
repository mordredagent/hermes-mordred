"""Closed response shapes for the Desktop page: what may leave this process, and nothing else.

Every function here copies named keys only, checks each value's type (ints,
bools, codes from the closed sets below) and drops everything else, so a
corrupt metadata file or a library that grows a field can never put an
address, a folder name or free text into ``/status``, ``/imports/status``,
``/mail/*`` answers, job views or events. The code sets are the API's closed
sets: the page keeps a ``MESSAGES`` entry for each (see the page tests).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

__all__ = [
    "DATABASE_CODES",
    "IMAP_HINTS",
    "IMPORT_STATE_CODES",
    "MAIL_CODES",
    "MAIL_FETCH_CODES",
    "MAIL_FORGET_CODES",
    "MAIL_SETUP_CODES",
    "VAULT_CODES",
    "closed",
    "forgotten_projection",
    "hint_of",
    "imports_projection",
    "imports_refused",
    "mail_projection",
    "setup_flow_view",
]

#: Import-store states reported by ``/status.imports.code`` (a gate refusal is a state, not an error).
IMPORT_STATE_CODES: Final = frozenset(
    {
        "not_armed",
        "conversion_pending",
        "unprotected_process",
        "no_key",
        "plaintext_store",
        "store_unavailable",
        "busy",
        "profile_mismatch",
        "schema_newer",
        "unkeyed_connection",
        "store_uninitialised",
        "unsupported_platform",
        "disk_full",
    }
)
_IMPORT_FALLBACK: Final = "store_unavailable"

#: ``ImapError.hint`` values (SPEC "IMAP failure hints"); any other hint is dropped.
IMAP_HINTS: Final = frozenset({"authentication_failed", "server_alert", "login_disabled", "gmail_app_password_length"})

#: ``MailSetupError`` codes plus the route's own refusals.
MAIL_SETUP_CODES: Final = frozenset(
    {
        "invalid_address",
        "invalid_host",
        "invalid_account",
        "invalid_password",
        "too_many_addresses",
        "mail_already_configured",
        "mail_setup_flow_expired",
        "mail_setup_busy",
        "mail_setup_stale",
        "invalid_selection",
        "touch_id_policy_mismatch",
        "sync_in_progress",
        "store_path_unsafe",
        "tee_unavailable",
        "tee_auth_cancelled",
        "imap_unreachable",
        "imap_auth_failed",
        "imap_protocol",
        "imap_command_refused",
        "routing_unavailable",
        "egress_unsupported",
        # the route's own
        "unsupported_platform",
        "memory_encryption_required",
        "invalid_body",
        "mail_setup_failed",  # an unexpected library failure (logged by class name only)
    }
)
MAIL_SETUP_FALLBACK: Final = "mail_setup_failed"

#: ``imap_sync.ERROR_CODES`` (a test pins that every one of them is here) plus the route's refusals.
MAIL_FETCH_CODES: Final = frozenset(
    {
        "unsupported_platform",
        "mail_not_configured",
        "memory_encryption_required",
        "custody_busy",
        "import_store_unavailable",
        "not_armed",
        "conversion_pending",
        "unprotected_process",
        "no_key",
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
        "credentials_left",
        # the route's own
        "invalid_body",
        "mail_fetch_busy",
    }
)
MAIL_FETCH_FALLBACK: Final = "fetch_failed"

#: What ``forget()`` can refuse with or warn about (the CLI's codes), plus the route's refusals.
MAIL_FORGET_CODES: Final = frozenset(
    {
        "forget_confirm_mismatch",
        "credentials_changed",
        "credentials_left",
        "key_left",
        "account_unknown",
        "account_mismatch",
        "invalid_account",
        "sync_in_progress",
        "store_path_unsafe",
        "tee_unavailable",
        "tee_auth_cancelled",
        "secrets_corrupt",
        "import_store_unavailable",
        *IMPORT_STATE_CODES,
        "memory_encryption_required",
        "invalid_body",
        "fetch_failed",
    }
)
MAIL_FORGET_FALLBACK: Final = "fetch_failed"  # the CLI's catch-all for ``mail forget``
_FORGET_WARNING_FALLBACK: Final = "store_unavailable"  # a store code that left the cursors behind

MAIL_CODES: Final = MAIL_SETUP_CODES | MAIL_FETCH_CODES | MAIL_FORGET_CODES

#: ``/databases/*`` errors and ``attention`` codes.
DATABASE_CODES: Final = frozenset(
    {
        "databases_unsupported",
        "databases_failed",
        "plaintext_in_armed_home",
        "stale_pending",
        "decrypt_pending",
        "journal",
        "invalid_body",
        "invalid_request",
    }
)

#: ``/vault/*`` and ``/memory/enable`` (macOS) codes.
VAULT_CODES: Final = frozenset(
    {
        "vault_exists",
        "vault_required",
        "vault_flow_expired",
        "vault_anchor_stale",
        "env_optout",
        "env_required",
        "memory_operation_in_progress",
        "memory_encryption_failed",
        "unsupported_platform",
        "invalid_body",
    }
)

_ROLES: Final = ("all", "inbox", "sent")
_ACCOUNT_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")  # secrets.ACCOUNT_RE, without importing the mail stack
#: A flow id is an opaque token (``secrets.token_urlsafe`` or hex), never derived from input.
_FLOW_ID_RE: Final = re.compile(r"[A-Za-z0-9_-]{8,64}")
_SOURCES: Final = ("telegram", "mail")
_COUNTS: Final = ("conversations", "messages", "parts")
_CURSOR_NUMBERS: Final = ("uidvalidity", "epoch", "uid", "low")


def closed(code: object, allowed: frozenset[str], fallback: str) -> str:
    """``code`` when it is a member of ``allowed``, else ``fallback`` (never free text)."""
    return code if isinstance(code, str) and code in allowed else fallback


def hint_of(exc: BaseException) -> str | None:
    hint = getattr(exc, "hint", None)
    return hint if isinstance(hint, str) and hint in IMAP_HINTS else None


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _bool_or_none(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _time_or_none(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    return int(value)


# -- imports ------------------------------------------------------------------------------


def imports_refused(code: object) -> dict[str, Any]:
    """A gate or store refusal as a state; every unknown code is ``store_unavailable``."""
    return {"available": False, "code": closed(code, IMPORT_STATE_CODES, _IMPORT_FALLBACK), "sources": {}}


def imports_projection(status: object) -> dict[str, Any]:
    """``ImportStore.status()`` reduced to per-source totals (all accounts) of the two known sources."""
    sources = status.get("sources") if isinstance(status, Mapping) else None
    if not isinstance(sources, Mapping):
        return imports_refused(_IMPORT_FALLBACK)
    projected: dict[str, dict[str, int]] = {}
    for source in _SOURCES:
        counts = sources.get(source)
        counts = counts if isinstance(counts, Mapping) else {}
        projected[source] = {key: _count(counts.get(key)) for key in _COUNTS}
    return {"available": True, "code": None, "sources": projected}


# -- mail -----------------------------------------------------------------------------------


def _scope(roles: object) -> list[str]:
    values = roles if isinstance(roles, list | tuple) else ()
    return [role for role in _ROLES if role in values]


def _last_attempt(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    error = value.get("error")
    return {
        "at": _time_or_none(value.get("at")),
        "error": None if error is None else closed(error, MAIL_FETCH_CODES, MAIL_FETCH_FALLBACK),
        "partial": _bool_or_none(value.get("partial")),
    }


def _last_success(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    at = _time_or_none(value.get("at"))
    return None if at is None else {"at": at}


def _cursors(value: object) -> dict[str, dict[str, dict[str, int]]]:
    if not isinstance(value, Mapping):
        return {}
    found: dict[str, dict[str, dict[str, int]]] = {}
    for role in _ROLES:
        kinds = value.get(role)
        if not isinstance(kinds, Mapping):
            continue
        entry: dict[str, dict[str, int]] = {}
        for kind in ("forward", "backfill"):
            numbers = kinds.get(kind)
            if isinstance(numbers, Mapping):
                entry[kind] = {
                    name: numbers[name]
                    for name in _CURSOR_NUMBERS
                    if isinstance(numbers.get(name), int) and not isinstance(numbers.get(name), bool)
                }
        if entry:
            found[role] = entry
    return found


def mail_projection(flags: object, status: object, *, residue: bool = False) -> dict[str, Any]:
    """``/status.mail``: the account label, scope, policy, last attempt and success, cursors. Never the address.

    ``flags`` is ``MailSecretStore.flags()`` (``None`` when nothing is sealed);
    ``status`` is ``imap_status(store, flags)`` when the import store opened,
    else ``None`` (then only the flags are reported). A sealed file whose flags
    are missing or unreadable is the residue state ``credentials_left``.
    """
    account = flags.get("account") if isinstance(flags, Mapping) else None
    if not isinstance(account, str) or not _ACCOUNT_RE.fullmatch(account):
        return {"configured": False, "residue": "credentials_left"} if residue else {"configured": False}
    assert isinstance(flags, Mapping)
    view: dict[str, Any] = {
        "configured": True,
        "account": account,
        "gmail": _bool_or_none(flags.get("gmail")),
        "scope": _scope(flags.get("roles")),
        "touch_id": _bool_or_none(flags.get("touch_id")),
    }
    if not isinstance(status, Mapping) or status.get("configured") is not True:
        return view
    # ``imap_status`` reports the last attempt as ``last_fetch`` (``last_attempt`` is accepted too) and the
    # last success as ``last_success``; an older one without ``last_success`` had one record, a success
    # when it carried no error.
    attempt = status["last_attempt"] if "last_attempt" in status else status.get("last_fetch")
    if "last_success" in status:
        success = status["last_success"]
    else:
        success = attempt if isinstance(attempt, Mapping) and attempt.get("error") is None else None
    view["last_attempt"] = _last_attempt(attempt)
    view["last_success"] = _last_success(success)
    view["cursors"] = _cursors(status.get("cursors"))
    return view


def forgotten_projection(done: object) -> dict[str, Any]:
    """A ``Forgotten`` result: counts, a bool and residue codes only."""
    warnings = getattr(done, "warnings", ())
    codes = [
        closed(code, MAIL_FORGET_CODES, _FORGET_WARNING_FALLBACK)
        for code in (warnings if isinstance(warnings, list | tuple) else ())
    ]
    return {
        "ok": True,
        "had_credentials": getattr(done, "had_credentials", False) is True,
        "deleted_messages": _count(getattr(done, "deleted_messages", 0)),
        "cursors_deleted": _count(getattr(done, "cursors_deleted", 0)),
        "warnings": list(dict.fromkeys(codes)),
    }


def setup_flow_view(flow: object) -> dict[str, Any]:
    """``/mail/setup/start``'s answer; folder names appear only for the ``folders`` step."""
    step = getattr(flow, "step", None)
    step = step if step in ("folders", "done") else "done"
    flow_id = getattr(flow, "flow_id", None)
    account = getattr(flow, "account", None)
    question = getattr(flow, "question", None)
    view: dict[str, Any] = {
        "ok": True,
        "flow_id": flow_id if isinstance(flow_id, str) and _FLOW_ID_RE.fullmatch(flow_id) else "",
        "step": step,
        "question": question if step == "folders" and question in ("all_mail", "sent") else None,
        "gmail": getattr(flow, "gmail", False) is True,
        "account": account if isinstance(account, str) and _ACCOUNT_RE.fullmatch(account) else None,
        "folders": [],
    }
    if step == "folders":
        for entry in getattr(flow, "folders", ()) or ():
            name, display = getattr(entry, "name", None), getattr(entry, "display", None)
            if isinstance(name, str) and isinstance(display, str):
                view["folders"].append({"id": name, "display": display[:200]})
    return view
