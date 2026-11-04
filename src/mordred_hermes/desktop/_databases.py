"""Shared passive database capability projected onto the unchanged Desktop v4 API.

Observation never opens SQL, constructs a provider or acquires native custody.
Explicit maintenance remains separate from passive rendering.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..dbcrypt import DatabaseStatus

__all__ = ["database_status_projection", "encrypt_answer", "status_object"]


def database_status_projection(status: DatabaseStatus) -> dict[str, object]:
    """Project passive capability onto the exact v4 shapes, without asserting unknown facts.

    ``supported`` means no known static unavailability; ``armed`` is configured
    intent, never proof of encryption. Version 4 has no capability/reason field.
    Pending state, database classification and backup counts need facts that
    DatabaseStatus does not carry, so they remain explicitly unknown.
    """
    if status.capability == "unavailable":
        return {"supported": False}
    return {
        "supported": True,
        "armed": status.configured,
        "encrypt_pending": None,
        "decrypt_pending": None,
        "journal": None,
        "runtime_protected": status.authenticated and status.capability == "available",
        "databases": [],
        "plaintext_backups": None,
    }


def status_object(
    home: Path, *, platform: str | None = None, sqlcipher: bool | None = None, environ: Mapping[str, str] | None = None
) -> dict[str, object]:
    """Passive shared observation; legacy arguments do not grant database authority."""
    from .. import dbcrypt

    return database_status_projection(dbcrypt.database_status(home))


def _attention(code: str) -> dict[str, Any]:
    return {"ok": True, "action": "attention", "code": code}


def encrypt_answer(home: Path, facts: Mapping[str, Any]) -> dict[str, Any]:
    """The total decision over ``facts`` (a :func:`status_object`); schedules when that is the answer.

    Raises ``OSError`` when scheduling fails (the route answers ``databases_failed``).
    """
    from .. import dbcrypt
    from ..dbcrypt import _migrate

    if not facts.get("supported") or any(
        facts.get(field) is None for field in ("encrypt_pending", "decrypt_pending", "journal")
    ):
        return _attention("databases_failed")
    plaintext = any(entry.get("state") == "plaintext" for entry in facts.get("databases", ()))
    if facts.get("journal"):
        return _attention("journal")
    if facts.get("decrypt_pending"):
        return _attention("decrypt_pending")
    if not facts.get("armed"):
        if not facts.get("encrypt_pending"):
            _migrate.schedule(dbcrypt.root_home(home))
        return {"ok": True, "action": "scheduled", "restart_required": True}
    if facts.get("encrypt_pending"):
        return _attention("stale_pending")  # startup skips a pending conversion once armed
    if plaintext:
        return _attention("plaintext_in_armed_home")  # quit Hermes, then `hermes-mordred databases encrypt`
    if not facts.get("runtime_protected"):
        return {"ok": True, "action": "needs_restart", "restart_required": True}
    return {"ok": True, "action": "done"}
