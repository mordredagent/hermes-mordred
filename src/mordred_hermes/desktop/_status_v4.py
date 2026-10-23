"""The ``/status`` sections for ``client_version >= 4``: macOS facts, fixed shapes elsewhere.

``vault``, ``databases``, ``imports``, ``mail`` and ``telegram_archive``, each
built from files, the read-only import store and the mail flags only: nothing
here unlocks the vault, prompts, initialises a schema or creates a file. A
failure in one section is a state of that section, never a 500. The seams are
reached through :mod:`._seams` at call time.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from . import _databases, _projections, _seams, _vault

__all__ = ["databases_safe", "imports_sections", "sections", "vault_facts_safe"]

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
        }
    vault, databases, imports = await asyncio.gather(
        asyncio.to_thread(vault_facts_safe, home),
        asyncio.to_thread(databases_safe, home, platform),
        asyncio.to_thread(imports_sections, home, platform),
    )
    return {"vault": vault, "databases": databases, **imports}


def vault_facts_safe(home: Path) -> dict[str, Any]:
    try:
        return _vault.facts(home, _seams.vault_root(), platform="darwin")
    except Exception as exc:
        _log.warning("mordred desktop vault facts unreadable (%s)", type(exc).__name__)
        return dict(_UNSUPPORTED_VAULT)


def databases_safe(home: Path, platform: str) -> dict[str, Any]:
    try:
        return _databases.status_object(home, platform=platform, sqlcipher=_seams.sqlcipher_available())
    except Exception as exc:
        _log.warning("mordred desktop database status unreadable (%s)", type(exc).__name__)
        return {"supported": _seams.sqlcipher_available(), "code": "databases_failed"}


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
    """``imports``, ``mail`` and ``telegram_archive``: read-only store, flags only, nothing unlocked."""
    if platform != "darwin":
        return {
            "imports": _projections.imports_refused("unsupported_platform"),
            "mail": {"configured": False},
            "telegram_archive": dict(_TELEGRAM_ARCHIVE),
        }
    store: Any = None
    opened: Any = None
    try:
        store = opened = _seams.open_store_readonly(home)
        imports = _projections.imports_projection(store.status())
    except Exception as exc:  # a gate or store refusal is a state (ImportRefused carries the code)
        imports = _projections.imports_refused(_seams.store_refusal(exc))
    if not imports["available"]:
        store = None
    flags, residue = _mail_flags()
    mail_status: Any = None
    try:
        if store is not None and flags:
            try:
                mail_status = _seams.imap_status(store, flags)
            except Exception as exc:
                _log.warning("mordred desktop mail status unreadable (%s)", type(exc).__name__)
    finally:
        # The read-only store keeps one SQLCipher connection for its life: close it here,
        # not in a finaliser, so a status poll never leaves a reader open.
        closer = getattr(opened, "close", None)
        if callable(closer):
            closer()
    return {
        "imports": imports,
        "mail": _projections.mail_projection(flags, mail_status, residue=residue),
        "telegram_archive": dict(_TELEGRAM_ARCHIVE),
    }
