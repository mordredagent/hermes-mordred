"""``/vault/*`` and ``/databases/*``: the macOS ceremonies of Desktop step 1 (a sub-router of ``api.router``).

The vault is prepared, acknowledged, then committed (:mod:`._vault`); the
databases are only ever scheduled or reported (:mod:`._databases`). Shared
helpers (``sys``, ``_home``, ``_error``) are read from :mod:`.api` and the
seams, registries and ceremony lock from :mod:`._seams`, both at call time, so
a test replaces them in one place.
"""

from __future__ import annotations

import asyncio
import logging
from types import ModuleType
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import _databases, _seams, _status_v4, _vault
from ._body import read_object

router = APIRouter()
_log = logging.getLogger(__name__)


def _api() -> ModuleType:
    from . import api

    return api


@router.post("/vault/prepare")
async def vault_prepare(request: Request) -> Any:
    """Body ``{}``. Generate the recovery passphrase in memory and show it BEFORE anything is created.

    Answers ``{"ok": true, "flow_id", "passphrase": [8 words], "passphrase_reused": false}``;
    nothing on disk changes. An existing vault whose ``.env`` is not enrolled
    gets a flow without a passphrase (``passphrase: null, passphrase_reused:
    true``): its phrase is the one shown at its creation. ``vault_exists`` when
    there is nothing to do, ``env_optout`` when the owner restored a plaintext
    ``.env``. One flow at a time (a new one replaces it), TTL 600 s.
    """
    api = _api()
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    if api.sys.platform != "darwin":
        return api._error("unsupported_platform")
    state = await asyncio.to_thread(_vault.facts, api._home(), _seams.vault_root(), platform="darwin")
    answer = _vault.prepare_answer(_seams.vault_flows(), state)
    return answer if answer["ok"] else JSONResponse(answer, status_code=200)


@router.post("/vault/{flow_id}/commit")
async def vault_commit(flow_id: str, request: Request) -> Any:
    """Body ``{"unattended": bool}``. Create the vault with the prepared passphrase, enroll ``.env``.

    ``{"ok": true, "passphrase_reused": bool}``; ``vault_flow_expired`` (TTL,
    replaced, restart: nothing was created), ``vault_exists``, ``env_optout``,
    ``vault_anchor_stale`` (with ``anchor_store``, ``anchor_identity`` and,
    only for a legacy anchor over an empty vault directory, ``remedy``; checked
    BEFORE the wizard, which would otherwise migrate a legacy anchor) or
    ``memory_encryption_failed``. ``unattended`` applies only to a device key
    created here (absent: the backend default, as ``setup``); an existing key
    keeps its policy.
    """
    api = _api()
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    unattended = body.get("unattended")
    if not (unattended is None or isinstance(unattended, bool)):
        return api._error("invalid_body")
    if api.sys.platform != "darwin":
        return api._error("unsupported_platform")
    flows = _seams.vault_flows()
    flow = flows.get(flow_id)
    if flow is None:
        return api._error("vault_flow_expired")
    home, root, platform = api._home(), _seams.vault_root(), api.sys.platform
    return await _seams.run_ceremony(
        lambda: _vault.commit(home=home, root=root, platform=platform, flow=flow, flows=flows, unattended=unattended)
    )


@router.get("/databases/status")
async def databases_status() -> Any:
    """The ``databases`` object of ``/status`` alone (after the restart control, when status is too heavy)."""
    api = _api()
    return {"ok": True, **await asyncio.to_thread(_status_v4.databases_safe, api._home(), api.sys.platform)}


@router.post("/databases/encrypt")
async def databases_encrypt(request: Request) -> Any:
    """Body ``{"dry_run": bool}``. Schedules the conversion for the next start, or reports why not.

    ``{"ok": true, "action": "dry_run" | "scheduled" | "attention" | "needs_restart" | "done", …}``
    (``restart_required`` with ``scheduled`` / ``needs_restart``, ``code`` with
    ``attention``: ``journal``, ``decrypt_pending``, ``stale_pending``,
    ``plaintext_in_armed_home``); ``databases_unsupported`` off macOS or without
    SQLCipher; ``databases_failed`` when scheduling failed (re-read the status).
    No key is needed and none is unwrapped: the conversion runs at startup.
    """
    api = _api()
    body = await read_object(request)
    if isinstance(body, JSONResponse):
        return body
    dry_run = body.get("dry_run", False)
    if not isinstance(dry_run, bool):
        return api._error("invalid_body")
    if api.sys.platform != "darwin" or not await asyncio.to_thread(_seams.sqlcipher_available):
        return api._error("databases_unsupported")
    if dry_run:
        return {"ok": True, "action": "dry_run"}
    home = api._home()

    def decide() -> dict[str, Any]:
        facts = _databases.status_object(home, platform="darwin", sqlcipher=True)
        return _databases.encrypt_answer(home, facts)

    try:
        return await asyncio.to_thread(decide)
    except Exception as exc:
        _log.warning("mordred desktop database encryption not scheduled (%s)", type(exc).__name__)
        return api._error("databases_failed")
