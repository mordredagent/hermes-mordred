"""Shared passive database capability projected onto the Desktop v4 API, and its one decision table.

Observation never opens SQL, constructs a provider or acquires native custody.
Facts come from ``lstat``; the single content read is Mordred's own non-secret,
bounded startup record (:func:`._startup.read_outcome`). The routes only schedule,
cancel or report: :mod:`..dbcrypt._startup` converts at the next start.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from ..dbcrypt import DatabaseIntent, DatabaseStatus

__all__ = ["cancel_answer", "database_status_projection", "encrypt_answer", "status_object"]

_FACTS: Final = ("armed", "encrypt_pending", "decrypt_pending", "journal")

#: What a recorded startup outcome asks of the owner; any other value is ``startup_refused``.
_OUTCOME_CODES: Final = {
    "busy": "startup_busy",
    "memory_not_enabled": "startup_memory_required",
    "source_unavailable": "startup_key_unavailable",
    "too_large": "startup_too_large",
    "auth_interrupted": "startup_auth_interrupted",
}


def database_status_projection(
    status: DatabaseStatus,
    intent: DatabaseIntent | None = None,
    *,
    runtime_protected: bool = False,
    plaintext_backups: int | None = None,
    startup_outcome: str | None = None,
) -> dict[str, object]:
    """Project passive facts onto the exact v4 shape, without asserting unknown ones.

    ``supported`` is false only for known static unavailability. ``armed`` is the
    marker alone, never proof of encryption. An unsafe or unobserved intent is
    ``None``, which never means absent. ``databases`` stays ``[]``, meaning unknown:
    classifying a file needs SQL.
    """
    if status.capability == "unavailable":
        return {"supported": False}
    facts = {} if intent is None or intent.unsafe else {field: getattr(intent, field) for field in _FACTS}
    return {
        "supported": True,
        **{field: facts.get(field) for field in _FACTS},
        "runtime_protected": runtime_protected,
        "databases": [],
        "plaintext_backups": plaintext_backups,
        "startup_outcome": startup_outcome,
    }


def _runtime_protected(root: Path) -> bool:
    """Observe this process's installed authority: native, live, for this root, behind the shim.

    Never ``check()``, an unwrap, SQL or an environment key. A failed observation is
    "not protected", so polling cannot claim protection or fail the status answer.
    """
    from .. import dbcrypt
    from ..dbcrypt import _shim

    try:
        provider = dbcrypt._runtime._PROVIDER
        if provider is None or not provider.runtime_native:
            return False
        authority = provider.current_authority
        if authority is None or authority.terminal:
            return False
        return authority.root == Path(os.path.realpath(root)) and _shim.is_installed()
    except Exception:
        return False


def _startup_outcome(root: Path) -> str | None:
    """The startup record's code. This bounded read is the one exception to metadata-only polling.

    Only called while a conversion is scheduled: without a schedule no answer depends
    on the record, and a legacy shared ``mordred/`` would read as a refusal.
    """
    from ..dbcrypt import _startup

    try:
        return _startup.read_outcome(root)
    except Exception:
        return "refused"  # Present and unusable: counts as "any other", never as no record.


def _plaintext_backups(root: Path) -> int | None:
    """Archives that may hold plaintext copies: listed, never opened. ``None`` when not listable."""
    from ..dbcrypt import _migrate

    try:
        return len(_migrate.plaintext_backups(root))
    except OSError:
        return None


def status_object(
    home: Path, *, platform: str | None = None, sqlcipher: bool | None = None, environ: Mapping[str, str] | None = None
) -> dict[str, object]:
    """Passive shared observation; legacy arguments do not grant database authority."""
    from .. import dbcrypt

    status = dbcrypt.database_status(home)
    if status.capability == "unavailable":
        return database_status_projection(status)
    intent = dbcrypt.database_intent(home)
    root = dbcrypt.root_home(home)
    known = not intent.unsafe
    return database_status_projection(
        status,
        intent,
        runtime_protected=_runtime_protected(root),
        plaintext_backups=_plaintext_backups(root) if known else None,
        startup_outcome=_startup_outcome(root) if known and intent.encrypt_pending else None,
    )


def _attention(code: str) -> dict[str, Any]:
    return {"ok": True, "action": "attention", "code": code}


def _unknown(facts: Mapping[str, Any]) -> bool:
    return any(facts.get(field) is None for field in _FACTS)


def encrypt_answer(home: Path, facts: Mapping[str, Any]) -> dict[str, Any]:
    """The total decision over ``facts`` (a :func:`status_object`); schedules when that is the answer.

    The first matching row decides. The journal precedes every other fact, because a
    record can coexist with a journal. Raises when the size or the schedule fails (the
    route answers ``databases_failed``).
    """
    from .. import dbcrypt
    from ..dbcrypt import _migrate, _startup

    if _unknown(facts):
        return _attention("databases_failed")
    if facts["journal"]:
        return _attention("journal")
    if facts["decrypt_pending"]:
        return _attention("decrypt_pending")
    if facts["armed"]:
        if facts["encrypt_pending"]:
            return _attention("stale_pending")  # startup refuses a pending conversion once armed
        if not facts.get("runtime_protected"):
            return {"ok": True, "action": "needs_restart", "restart_required": True}
        return {"ok": True, "action": "done"}
    if not facts["encrypt_pending"]:
        root = dbcrypt.root_home(home)
        if _startup.conversion_too_large(root):
            return _attention("startup_too_large")
        _migrate.schedule(root)
    elif (outcome := facts.get("startup_outcome")) is not None:
        return _attention(_OUTCOME_CODES.get(outcome, "startup_refused"))
    return {"ok": True, "action": "scheduled", "restart_required": True}


def cancel_answer(home: Path, facts: Mapping[str, Any]) -> dict[str, Any]:
    """Remove a schedule and its startup record; never converts, and refuses once one has started.

    ``_migrate.unschedule`` rechecks the journal and marker in its own transaction, so
    a conversion that starts after ``facts`` were read still refuses.
    """
    from .. import dbcrypt
    from ..dbcrypt import _migrate

    if _unknown(facts):
        return _attention("databases_failed")
    if facts["journal"] or facts["armed"]:
        return _attention("databases_cancel_refused")
    try:
        _migrate.unschedule(dbcrypt.root_home(home))
    except _migrate.MigrationError:
        return _attention("databases_cancel_refused")
    return {"ok": True, "action": "cancelled"}
