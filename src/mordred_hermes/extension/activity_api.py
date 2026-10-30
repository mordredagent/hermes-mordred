"""Activity-batch handlers for the extension WebSocket API (``activity_batch_v1``).

:class:`mordred_hermes.extension.api._Connection` dispatches two authed frame
types here; this module keeps their logic out of the already large ``api.py``.
Only the paired browser extension reaches them (principal
:data:`EXTENSION_PRINCIPAL`); the page principal is refused before dispatch.

- ``activity_batch`` — size check on the raw frame, then the configured
  receiver (``ExtensionAPIServer.activity_receiver``) → ``activity_ack`` /
  ``activity_refused``. No receiver means ``store_unavailable``.
- ``activity_status`` — content-free collection state.

Logs and replies carry identifiers, counts and reason codes only — never batch
content, tokens or codes.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from ..activity.contracts import PeerPrincipal

if TYPE_CHECKING:
    from ..activity.config import ActivityConfig
    from .api import _Connection

DEFAULT_MAX_BATCH_BYTES = 256 * 1024
# The extension API's raw text-frame ceiling (api.MAX_WS_FRAME_CHARS); a config
# value above it could never be reached.
_MAX_BATCH_BYTES_CEILING = 4 * 1024 * 1024
_MIN_BATCH_BYTES = 1024
ACTIVITY_CAPABILITY = "activity_batch_v1"
#: Every batch the paired extension submits is attributed to this principal; trust and permitted use come
#: from it, never from the payload.
EXTENSION_PRINCIPAL = PeerPrincipal(peer_id="extension", kind="browser")
_REPLY_TYPES = frozenset({"activity_ack", "activity_refused"})

_log = logging.getLogger(__name__)
_T = TypeVar("_T")


async def _in_executor(func: Callable[..., _T], *args: Any) -> _T:
    # Flock-guarded file I/O and SQLite transactions stay off the event loop.
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


def _refused(mid: Any, reason: str) -> dict[str, Any]:
    return {"id": mid, "type": "activity_refused", "reason": reason}


# --------------------------------------------------------------------------- #
# Configuration probes (lazy: the activity core is optional at import time)
# --------------------------------------------------------------------------- #


def resolve_max_batch_bytes(home: Path) -> int:
    """``max_batch_bytes`` from the activity config, clamped; default 262144."""
    try:
        from ..activity.config import ActivityConfig

        value = ActivityConfig.load(home).max_batch_bytes
    except Exception as exc:
        _log.debug("activity config unavailable for the batch size limit (%s)", type(exc).__name__)
        return DEFAULT_MAX_BATCH_BYTES
    return max(_MIN_BATCH_BYTES, min(value, _MAX_BATCH_BYTES_CEILING))


def _activity_config(home: Path) -> ActivityConfig | None:
    try:
        from ..activity.config import ActivityConfig

        return ActivityConfig.load(home)
    except Exception as exc:
        _log.debug("activity config unavailable (%s)", type(exc).__name__)
        return None


def read_activity_switches(home: Path) -> tuple[bool, bool] | None:
    """``(feature_enabled, collecting)`` from the activity config, or ``None``.

    ``collecting`` is false also while ``excluded_sites`` is invalid (the receiver refuses batches then).
    """
    config = _activity_config(home)
    return None if config is None else (config.enabled, config.collecting)


def gate_refusal_code(home: Path) -> str | None:
    """The protection gate's refusal code, ``None`` when it passes."""
    try:
        from ..activity._gate import check_protection

        refusal = check_protection(home)
    except Exception as exc:
        _log.debug("activity protection gate unavailable (%s)", type(exc).__name__)
        return "store_unavailable"
    return None if refusal is None else str(refusal.code)


def collection_status(home: Path) -> tuple[str, str | None]:
    """``(enabled|disabled|unavailable, reason)`` — content-free; ``disabled`` carries the receiver's refusal
    code (``collection_disabled`` or ``excluded_sites_invalid``)."""
    config = _activity_config(home)
    if config is None:
        return "unavailable", "store_unavailable"
    refusal = config.collection_refusal
    if refusal is not None:
        return "disabled", refusal
    code = gate_refusal_code(home)
    return ("enabled", None) if code is None else ("unavailable", code)


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #


def _ingest(receiver: Any, principal: PeerPrincipal, batch: Mapping[str, Any]) -> dict[str, Any]:
    try:
        reply = receiver.ingest(principal, batch)
    except Exception as exc:
        _log.warning("activity receiver failed (%s, peer=%s)", type(exc).__name__, principal.peer_id)
        return {"type": "activity_refused", "reason": "store_unavailable"}
    if not isinstance(reply, dict) or reply.get("type") not in _REPLY_TYPES:
        _log.warning("activity receiver returned an unexpected reply (peer=%s)", principal.peer_id)
        return {"type": "activity_refused", "reason": "store_unavailable"}
    return reply


async def on_activity_batch(conn: _Connection, msg: dict[str, Any]) -> None:
    mid = msg.get("id")
    principal = EXTENSION_PRINCIPAL
    if conn._frame_bytes > conn.activity_max_batch_bytes:
        _log.info("activity batch refused: batch_too_large (peer=%s)", principal.peer_id)
        await conn._send(_refused(mid, "batch_too_large"))
        return
    batch = msg.get("batch")
    if not isinstance(batch, dict):
        await conn._send(_refused(mid, "malformed"))
        return
    receiver = conn.activity_receiver
    if receiver is None:
        await conn._send(_refused(mid, "store_unavailable"))
        return
    reply = await _in_executor(_ingest, receiver, principal, batch)
    await conn._send({**reply, "id": mid})


async def on_activity_status(conn: _Connection, msg: dict[str, Any]) -> None:
    state: tuple[str, str | None] = ("unavailable", "store_unavailable")
    if conn.activity_receiver is not None:
        from .._home import hermes_home

        state = await _in_executor(collection_status, hermes_home())
    collection, reason = state
    await conn._send({"id": msg.get("id"), "type": "activity_status", "collection": collection, "reason": reason})
