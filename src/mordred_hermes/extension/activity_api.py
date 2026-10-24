"""Activity-batch handlers for the extension WebSocket API (``activity_batch_v1``).

:class:`mordred_hermes.extension.api._Connection` dispatches four frame types
here; this module keeps their logic out of the already large ``api.py``:

- ``activity_pair_init`` (pre-auth) — consume an activity pair code
  (:mod:`mordred_hermes.activity.peers`) → ``activity_pair_complete`` /
  ``activity_pair_fail``.
- ``activity_auth`` (pre-auth) — authenticate an activity peer token →
  ``activity_auth_ok`` / ``auth_fail``. The socket becomes an *activity
  principal*: only ``activity_batch`` and ``activity_status`` are dispatched.
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
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from ..activity import peers
from ..activity.peers import EXTENSION_PRINCIPAL, PeerPrincipal

if TYPE_CHECKING:
    from ..activity.config import ActivityConfig
    from .api import _Connection

DEFAULT_MAX_BATCH_BYTES = 256 * 1024
# The extension API's raw text-frame ceiling (api.MAX_WS_FRAME_CHARS); a config
# value above it could never be reached.
_MAX_BATCH_BYTES_CEILING = 4 * 1024 * 1024
_MIN_BATCH_BYTES = 1024
ACTIVITY_CAPABILITY = "activity_batch_v1"
# The only frames an activity principal may send after activity_auth.
ACTIVITY_ALLOWED = frozenset({"activity_batch", "activity_status"})
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
# Principal revalidation
# --------------------------------------------------------------------------- #


def authenticate_with_generation(peer_token: object) -> tuple[PeerPrincipal | None, bytes | None, str | None]:
    """Authenticate a peer token and capture its credential generation together."""
    principal, reason = peers.check_token(peer_token)
    if principal is None:
        return None, None, reason
    generation = peers.fingerprint(principal.peer_id)
    if generation is None:
        return None, None, "pairing_changed"
    return principal, generation, None


def principal_is_current(principal: PeerPrincipal | None, generation: bytes | None) -> bool:
    """Fail closed unless the activity peer's stored credential is unchanged.

    Checked Windows storage refusals propagate so the caller can classify them;
    any other read failure is revocation.
    """
    from ._windows_storage import ExtensionStorageError

    if principal is None or generation is None:
        return False
    try:
        current = peers.fingerprint(principal.peer_id)
    except ExtensionStorageError:
        raise
    except Exception:
        return False
    return current is not None and secrets.compare_digest(generation, current)


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #


async def on_activity_pair_init(conn: _Connection, msg: dict[str, Any]) -> None:
    mid = msg.get("id")
    try:
        result = await _in_executor(peers.handle_pair_init, msg.get("code"), msg.get("label"))
    except peers.PeerPairError as exc:
        await conn._send({"id": mid, "type": "activity_pair_fail", "reason": exc.reason})
        return
    # A new credential on this socket never inherits a prior principal.
    conn._invalidate_authentication()
    _log.info("activity peer paired (%s)", result["peer_id"])
    await conn._send({"id": mid, "type": "activity_pair_complete", **result})


async def on_activity_auth(conn: _Connection, msg: dict[str, Any]) -> None:
    conn._invalidate_authentication()
    principal, generation, reason = await _in_executor(authenticate_with_generation, msg.get("peer_token"))
    if principal is None or generation is None:
        await conn._send({"type": "auth_fail", "reason": reason or "invalid_token"})
        return
    conn.authed = True
    conn._activity_principal = principal
    conn._activity_generation = generation
    await conn._send(
        {
            "type": "activity_auth_ok",
            "peer_id": principal.peer_id,
            "capabilities": [ACTIVITY_CAPABILITY],
        }
    )


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
    principal = conn._activity_principal or EXTENSION_PRINCIPAL
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
