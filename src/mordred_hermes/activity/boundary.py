"""Trusted interaction registry and single-use launch permits for automatic review.

Hooks are observations, not admission: ``on_session_start`` /
``on_session_end`` / ``on_session_finalize`` copy ``(home, session_id, kind,
time)`` into a bounded in-memory deque and return. They never open the store,
call a model or start a thread; finalize additionally revokes unused permits.

Automatic review is admitted only by a Mordred-owned surface that knows its
foreground response was delivered (the extension ``chat`` handler, after
``chat_end``): it grants a single-use permit for the profile home and calls
:func:`try_automatic_review`, which consumes the permit and starts at most one
daemon thread per home. New foreground input revokes unused permits and asks a
running worker not to submit. Surfaces without that contract keep capture and
the explicit ``activity review`` command; automatic review is unavailable there.

Everything is keyed by ``os.path.realpath(home)``: one process may serve
several profiles, and the worker thread receives its home, configuration and
LLM facade explicitly (it never reads ``HERMES_HOME`` or the process home).
"""

from __future__ import annotations

import collections
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from .config import ActivityConfig
    from .review import AuditSink, ReconcileReport

__all__ = [
    "PERMIT_TTL_S",
    "Permit",
    "consume_permit",
    "grant_launch_permit",
    "on_session_end",
    "on_session_finalize",
    "on_session_start",
    "recent_events",
    "reconcile",
    "register_hooks",
    "revoke_permits",
    "try_automatic_review",
]

_LOG = logging.getLogger("mordred.activity.boundary")

#: An unconsumed permit lapses: admission belongs to the delivery that granted it.
PERMIT_TTL_S: Final = 300.0
_MAX_EVENTS: Final = 64
_MAX_SESSION_ID_CHARS: Final = 256
_AUX_TASK_DEFAULTS: Final = {"provider": "auto", "model": "", "timeout": 30}

#: ``(home realpath, session_id, kind, time)``, newest last; bounded, never persisted.
_events: collections.deque[tuple[str, str, str, float]] = collections.deque(maxlen=_MAX_EVENTS)
_lock = threading.Lock()
_permits: dict[str, Permit] = {}
#: Bumped by every revocation; a running worker compares it before submitting.
_epochs: dict[str, int] = {}
_workers: dict[str, threading.Lock] = {}


@dataclass(frozen=True)
class Permit:
    permit_id: str
    home: str
    session_id: str | None  # id of the foreground request that granted the permit (extension chat frame id), or None
    granted_at: float


def _key(home: Path | str) -> str:
    return os.path.realpath(home)


def _session(value: Any) -> str:
    ok = isinstance(value, str) and 0 < len(value) <= _MAX_SESSION_ID_CHARS
    return value if ok else ""


def _current_home() -> str:
    from .._home import hermes_home

    # Resolved per call: one process can serve several profiles.
    return _key(hermes_home())


# --------------------------------------------------------------------------- #
# Hook callbacks (observation only)
# --------------------------------------------------------------------------- #


def on_session_start(session_id: Any = None, **_kwargs: Any) -> None:
    _events.append((_current_home(), _session(session_id), "start", time.time()))


def on_session_end(session_id: Any = None, completed: Any = None, interrupted: Any = None, **_kwargs: Any) -> None:
    # A completion observation only: not proof of success, human origin, delivery or idle time.
    kind = "interrupted" if interrupted is True else "completed" if completed is True else "end"
    _events.append((_current_home(), _session(session_id), kind, time.time()))


def on_session_finalize(session_id: Any = None, **_kwargs: Any) -> None:
    home = _current_home()
    _events.append((home, _session(session_id), "finalize", time.time()))
    revoke_permits(home, "finalize")


def recent_events() -> tuple[tuple[str, str, str, float], ...]:
    return tuple(_events)


def register_hooks(ctx: Any) -> None:
    """Register the three observation hooks and, when the host supports it, the review task."""
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("on_session_finalize", on_session_finalize)
    register_task = getattr(ctx, "register_auxiliary_task", None)
    if register_task is None:
        return
    from .review import REVIEW_TASK

    try:
        register_task(
            REVIEW_TASK,
            display_name="Mordred activity review",
            description="Tool-free review of browser-activity episodes into candidate lessons (Mordred).",
            defaults=dict(_AUX_TASK_DEFAULTS),
        )
    except Exception as exc:  # a host may reject the key; capture and explicit review still work
        _LOG.warning("activity review auxiliary task not registered (%s)", type(exc).__name__)


# --------------------------------------------------------------------------- #
# Launch permits
# --------------------------------------------------------------------------- #


def grant_launch_permit(home: Path | str, session_id: str | None, now: float) -> Permit:
    """A single-use permit for ``home``; replaces any older one."""
    key = _key(home)
    permit = Permit(secrets.token_hex(8), key, session_id or None, now)
    with _lock:
        _permits[key] = permit
    return permit


def revoke_permits(home: Path | str, reason: str) -> int:
    """Drop the unused permit of ``home`` and ask a running worker not to submit."""
    key = _key(home)
    with _lock:
        dropped = _permits.pop(key, None)
        _epochs[key] = _epochs.get(key, 0) + 1
    if dropped is not None:
        _LOG.debug("activity launch permit revoked (%s)", reason)
    return int(dropped is not None)


def consume_permit(home: Path | str, session_id: str | None, now: float) -> Permit | None:
    """Take the permit of ``home`` once; ``session_id=None`` accepts any session's permit."""
    key = _key(home)
    with _lock:
        permit = _permits.get(key)
        if permit is None:
            return None
        if now - permit.granted_at > PERMIT_TTL_S or now < permit.granted_at:
            del _permits[key]
            return None
        if session_id is not None and permit.session_id != session_id:
            return None
        del _permits[key]
        return permit


def _epoch(key: str) -> int:
    with _lock:
        return _epochs.get(key, 0)


# --------------------------------------------------------------------------- #
# Admission and the worker
# --------------------------------------------------------------------------- #


def _load_config(home: Path) -> ActivityConfig:
    from .config import ActivityConfig

    return ActivityConfig.load(home)


def _protected(home: Path) -> bool:
    from ._gate import check_protection

    return check_protection(home) is None


def _worker(
    home: Path,
    config: ActivityConfig,
    llm: Any,
    now: float,
    cancelled: Callable[[], bool],
    sink: AuditSink,
    running: threading.Lock,
) -> None:
    from . import review

    try:
        store = review.open_review_store(home)
        review.reconcile_store(store, config, now, audit=sink)
        if not cancelled():
            review.run_one_pending(
                home,
                llm=llm,
                config=config,
                now=now,
                automatic=True,
                owner=f"auto:{os.getpid()}:{threading.get_ident()}",
                cancelled=cancelled,
                audit=sink,
                store=store,
            )
    except Exception as exc:  # a background review never surfaces in the foreground
        _LOG.warning("automatic activity review stopped (%s)", type(exc).__name__)
    finally:
        running.release()


def try_automatic_review(
    home: Path | str,
    *,
    llm: Any,
    now: float,
    thread_factory: Callable[..., Any] = threading.Thread,
) -> bool:
    """Start one background review for ``home`` if a permit, the mode and the gate allow it.

    Returns ``False`` without side effects unless ``review_mode`` is
    ``task_boundary``, the store is protected, and an unexpired permit for this
    home is consumed. At most one worker per home runs at a time.
    """
    key = _key(home)
    root = Path(key)
    config = _load_config(root)
    if not (config.enabled and config.review_mode == "task_boundary") or not _protected(root):
        return False
    if consume_permit(key, None, now) is None:
        return False
    with _lock:
        running = _workers.setdefault(key, threading.Lock())
    if not running.acquire(blocking=False):
        return False
    from . import review

    epoch = _epoch(key)
    sink = review.default_audit_sink()  # bound on this thread, not inside the worker
    try:
        thread = thread_factory(
            target=_worker,
            args=(root, config, llm, now, lambda: _epoch(key) != epoch, sink, running),
            name="mordred-activity-review",
            daemon=True,
        )
        thread.start()
    except BaseException:
        running.release()
        raise
    return True


def reconcile(home: Path | str, now: float) -> ReconcileReport:
    """Code-only catch-up for the next interactive use and the explicit CLI. No model call."""
    from . import review

    root = Path(_key(home))
    config = _load_config(root)
    return review.reconcile_store(review.open_review_store(root), config, now)
