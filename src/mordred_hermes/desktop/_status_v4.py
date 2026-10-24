"""The ``/status`` sections for ``client_version >= 4``: macOS facts, fixed shapes elsewhere.

``vault``, ``databases``, ``imports``, ``mail`` and ``telegram_archive``, each
built from passive database observations and mail flags only: nothing
here unlocks the vault, prompts, initialises a schema or creates a file. A
failure in one section is a state of that section, never a 500. The seams are
reached through :mod:`._seams` at call time.

``tools`` (``{direct, source}``, Hermes's direct tool calls read from
``config.yaml``) is reported on every platform: the setting is Hermes-wide.
So is ``activity`` (``{history, tools, source}``, the browser-history switches
``history_enabled`` / ``history_tools_enabled`` read from ``config.yaml``
through the activity config loader: no store, no protection gate).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from . import _databases, _projections, _seams, _vault

__all__ = ["activity_safe", "databases_safe", "imports_sections", "sections", "tools_safe", "vault_facts_safe"]

_log = logging.getLogger(__name__)

#: ``telegram_archive`` on a cold status: the legacy ``index.enc`` (its version and dialogs) is
#: AES-GCM ciphertext under a subkey of the sealed Telegram ``store_key``, and no status poll unwraps it.
_TELEGRAM_ARCHIVE: dict[str, Any] = {"legacy": None}
_UNSUPPORTED_VAULT: dict[str, Any] = {
    "exists": False,
    "env_enrolled": False,
    "env_injecting": False,
    "optout": False,
    "unattended": None,
}


async def sections(platform: str, home: Path) -> dict[str, Any]:
    if platform != "darwin":
        return {
            "vault": dict(_UNSUPPORTED_VAULT),
            "databases": {"supported": False},
            "imports": _projections.imports_refused("unsupported_platform"),
            "mail": {"configured": False},
            "telegram_archive": dict(_TELEGRAM_ARCHIVE),
            "tools": await asyncio.to_thread(tools_safe, home),
            "activity": await asyncio.to_thread(activity_safe, home),
        }
    vault, databases, imports, tools, activity = await asyncio.gather(
        asyncio.to_thread(vault_facts_safe, home),
        asyncio.to_thread(databases_safe, home, platform),
        asyncio.to_thread(imports_sections, home, platform),
        asyncio.to_thread(tools_safe, home),
        asyncio.to_thread(activity_safe, home),
    )
    return {"vault": vault, "databases": databases, **imports, "tools": tools, "activity": activity}


def tools_safe(home: Path) -> dict[str, Any]:
    """``{"direct": bool | None, "source": "config" | "default" | "unreadable"}``; never fails the status."""
    try:
        mode = _seams.tools_mode(home)
        direct, source = mode.get("direct"), mode.get("source")
        if isinstance(direct, bool) and source in ("config", "default"):
            return {"direct": direct, "source": source}
    except Exception as exc:
        _log.warning("mordred desktop tool-call mode unreadable (%s)", type(exc).__name__)
    return {"direct": None, "source": "unreadable"}


def activity_safe(home: Path) -> dict[str, Any]:
    """``{"history": bool | None, "tools": bool | None, "source": "config" | "unreadable"}``; never fails the
    status (an unreadable config.yaml is ``unreadable``, with both switches ``None``)."""
    try:
        state = _seams.activity_history(home)
        history, tools = state.get("history"), state.get("tools")
        if isinstance(history, bool) and isinstance(tools, bool):
            return {"history": history, "tools": tools, "source": "config"}
    except Exception as exc:
        _log.warning("mordred desktop browser-history switches unreadable (%s)", type(exc).__name__)
    return {"history": None, "tools": None, "source": "unreadable"}


def vault_facts_safe(home: Path) -> dict[str, Any]:
    try:
        return _vault.facts(home, _seams.vault_root(), platform="darwin")
    except Exception as exc:
        _log.warning("mordred desktop vault facts unreadable (%s)", type(exc).__name__)
        return dict(_UNSUPPORTED_VAULT)


def databases_safe(home: Path, platform: str) -> dict[str, Any]:
    try:
        return _databases.status_object(home)
    except Exception as exc:
        _log.warning("mordred desktop database status unreadable (%s)", type(exc).__name__)
        return {"supported": True, "code": "databases_failed"}


def _mail_flags() -> tuple[Any, bool]:
    """``(flags, residue)``; ``flags()`` raises ``credentials_left`` for a sealed file without readable flags."""
    try:
        secret_store = _seams.mail_secret_store()
        flags = secret_store.flags()
        return flags, bool(secret_store.residue())  # residue counts only when the flags name no valid setup
    except Exception as exc:
        residue = getattr(exc, "code", None) == "credentials_left"
        if not residue:
            _log.warning("mordred desktop mail flags unreadable (%s)", type(exc).__name__)
        return None, residue


def imports_sections(home: Path, platform: str) -> dict[str, Any]:
    """Flags only; record counts and cursors remain unknown without foreground SQL authority."""
    if platform != "darwin":
        return {
            "imports": _projections.imports_refused("unsupported_platform"),
            "mail": {"configured": False},
            "telegram_archive": dict(_TELEGRAM_ARCHIVE),
        }
    # Counts and cursors require SQL authority. A passive poll never acquires
    # that authority, including when a runtime provider happens to exist.
    flags, residue = _mail_flags()
    return {
        "imports": _projections.imports_refused("store_unavailable"),
        "mail": _projections.mail_projection(flags, None, residue=residue),
        "telegram_archive": dict(_TELEGRAM_ARCHIVE),
    }
