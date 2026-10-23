"""Hermes database encryption as the Desktop page sees it: facts, and schedule-or-report.

The Desktop backend never converts or arms the databases itself: it holds them
open and keeps a runtime lease, so a conversion can only run at the next
Hermes start (``dbcrypt.install`` runs a scheduled conversion before anything
opens a database). :func:`status_object` reads facts without a key, a Touch ID
prompt or a capture; :func:`encrypt_answer` turns them into the one answer of
the total state table (SPEC "Databases from the page") and schedules the
conversion when that is the answer. ``migrate()`` is never called from here.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = ["encrypt_answer", "key_material_valid", "runtime_protected", "status_object"]

_STATES = ("plaintext", "unreadable", "encrypted")


def key_material_valid(environ: Mapping[str, str]) -> bool:
    """``HERMES_MEMORY_KEY`` decodes to 32 bytes (no provider is called: nothing can be injected or unlocked)."""
    from ..keyvault._memory_hook import _decode_env_key

    key = _decode_env_key(environ)
    return key is not None and len(key) == 32


def _pending(root: Path) -> tuple[bool, bool, bool]:
    from ..dbcrypt import _migrate

    return (
        _migrate.pending_path(root).is_file(),
        _migrate.decrypt_pending_path(root).is_file(),
        _migrate.journal_path(root).is_file(),
    )


def runtime_protected(home: Path, *, platform: str, environ: Mapping[str, str]) -> bool:
    """This process runs the SQLCipher layer over an armed home with valid key material and nothing pending.

    The non-unlocking counterpart of ``activity._gate.check_protection``: the
    key check reads the environment value only, never ``dbcrypt._PROVIDER``.
    """
    if platform != "darwin":
        return False
    from .. import dbcrypt
    from ..dbcrypt import _shim

    root = dbcrypt.root_home(home)
    if not dbcrypt.armed(root) or any(_pending(root)):
        return False
    return _shim.is_installed() and key_material_valid(environ)


def status_object(
    home: Path, *, platform: str, sqlcipher: bool, environ: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """``/status.databases``: persisted intent, pending work, runtime protection and key-less discovery."""
    if platform != "darwin":
        return {"supported": False}
    from .. import dbcrypt
    from ..dbcrypt import _migrate

    env = os.environ if environ is None else environ
    root = dbcrypt.root_home(home)
    encrypt_pending, decrypt_pending, journal = _pending(root)
    databases = [
        {"relative": found.relative, "state": found.state}
        for found in _migrate.discover(root, None)
        if isinstance(found.relative, str) and found.state in _STATES
    ]
    return {
        "supported": sqlcipher,
        "armed": dbcrypt.armed(root),
        "encrypt_pending": encrypt_pending,
        "decrypt_pending": decrypt_pending,
        "journal": journal,
        "runtime_protected": runtime_protected(home, platform=platform, environ=env),
        "databases": databases,
        "plaintext_backups": len(_migrate.plaintext_backups(root)),
    }


def _attention(code: str) -> dict[str, Any]:
    return {"ok": True, "action": "attention", "code": code}


def encrypt_answer(home: Path, facts: Mapping[str, Any]) -> dict[str, Any]:
    """The total decision over ``facts`` (a :func:`status_object`); schedules when that is the answer.

    Raises ``OSError`` when scheduling fails (the route answers ``databases_failed``).
    """
    from .. import dbcrypt
    from ..dbcrypt import _migrate

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
