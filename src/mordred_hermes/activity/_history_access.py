"""Per-process access for the Hermes history surfaces: configuration, the gated store, the session budget.

- :func:`config` reads ``plugins.mordred_activity`` per call, cached by the
  file's modification time, size and inode, so ``activity use on|off`` (or a
  hand edit) applies from the next turn without restarting Hermes.
- :func:`reader` returns the profile's store only through the protection gate,
  on every call: :func:`._gate.check_protection`, a plaintext check of the
  file, the keyed opener (:func:`._gate._keyed_opener` refuses an unkeyed
  connection; :data:`OPENER` gives it the read bound
  :data:`.history.READ_BUSY_MS`, so the shim's schema probe never waits
  longer for a writer's lock) and a read-only check of the schema version and
  profile binding.
  It never creates, migrates or writes the store (that is the receiver's job;
  Hermes's own capture, :mod:`.capture_hermes`, writes only through the
  receiver), so a history read never takes a write lock. There is no plaintext path; a
  refusal raises :class:`._gate.ActivityRefused` and a profile that has
  recorded nothing yet raises :class:`NoHistory`. After a refusal the surfaces
  stay off for :data:`RETRY_AFTER_S` (the same refusal is raised as a
  :class:`CachedRefusal` without touching the store) so a refusing store
  cannot slow every turn; reporting a cached refusal never moves the deadline,
  only a refusal from a real attempt sets a new one.
- :data:`BUDGET` is the one per-session ledger of injected characters and
  shown episodes, shared by every surface.
- :func:`unavailable` is how a surface that goes on without history reports
  it: one ``activity.history_unavailable`` audit entry per process and code.

Nothing here reads ``HERMES_HOME`` except :func:`home`, which resolves the
active profile per call (one process may serve several profiles).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Final

from ._capture_audit import audit_history_unavailable
from ._gate import ActivityRefused, _keyed_opener, check_protection, refusal
from ._paths import PLUGIN_DATA_SUBPATH, STORE_NAME
from .config import ActivityConfig
from .matching import SessionBudget
from .store import SUPPORTED_SCHEMA_VERSION, ActivityStore

__all__ = [
    "BUDGET",
    "RETRY_AFTER_S",
    "CachedRefusal",
    "NoHistory",
    "config",
    "forget",
    "home",
    "reader",
    "session_key",
    "unavailable",
]

_LOG = logging.getLogger(__name__)
_MAX_CONFIGS: Final = 32
_MAX_SESSION_KEY_CHARS: Final = 256
#: After a refusal, the surfaces go on without history for this long before trying the store again.
RETRY_AFTER_S: Final = 60.0
#: The oldest schema the history queries can read (``query`` / ``page_title`` / ``page_text`` exist from v2).
MIN_READ_SCHEMA: Final = 2


def _read_opener(path: Path) -> sqlite3.Connection:
    """The keyed opener with the read bound: opening waits at most ``READ_BUSY_MS`` for a writer's lock."""
    from .history import READ_BUSY_MS

    return _keyed_opener(path, timeout=READ_BUSY_MS / 1000)


#: The opener for reads; production only ever uses the keyed opener (tests replace this seam).
OPENER = _read_opener

#: Injected characters and shown ``(episode id, revision)`` pairs per Hermes session.
BUDGET: Final = SessionBudget()

_lock = threading.Lock()
_configs: dict[str, tuple[tuple[int, int, int] | None, ActivityConfig]] = {}
#: Per home: (monotonic time until which reads are skipped, the refusal code to report meanwhile).
_retry: dict[str, tuple[float, str]] = {}
_logged: set[str] = set()


class NoHistory(Exception):
    """The profile has no ``mordred.db`` yet: nothing was recorded, so there is nothing to read."""


class CachedRefusal(ActivityRefused):
    """An earlier attempt's refusal, raised again without touching the store until its retry deadline."""


def home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def session_key(session_id: object, task_id: object = None) -> str:
    """The budget key of a Hermes session; calls without one share a single key."""
    for value in (session_id, task_id):
        if isinstance(value, str) and 0 < len(value) <= _MAX_SESSION_KEY_CHARS:
            return value
    return "-"


def _stamp(path: Path) -> tuple[int, int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def config(home: Path) -> ActivityConfig:
    """``plugins.mordred_activity`` of ``home``, re-read when ``config.yaml`` changed on disk."""
    path = home / "config.yaml"
    key = os.path.realpath(path)
    stamp = _stamp(path)
    with _lock:
        cached = _configs.get(key)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    loaded = ActivityConfig.load(home)
    with _lock:
        if key not in _configs and len(_configs) >= _MAX_CONFIGS:
            _configs.pop(next(iter(_configs)))
        _configs[key] = (stamp, loaded)
    return loaded


def _plaintext(path: Path) -> bool:
    from ..dbcrypt import _monitor

    return path.stat().st_size > 0 and _monitor.is_plaintext(path)


def _check_binding(store: ActivityStore, home: Path) -> None:
    """Schema version and profile binding, read without a write lock; raises :class:`ActivityRefused`."""
    from .history import read_meta

    meta = read_meta(store)
    version = meta.get("schema_version", "")
    if not version.isdigit() or int(version) < MIN_READ_SCHEMA:
        raise ActivityRefused(refusal("store_unavailable"))
    if int(version) > SUPPORTED_SCHEMA_VERSION:
        raise ActivityRefused(refusal("schema_newer"))
    if meta.get("profile_home") != os.path.realpath(home):
        raise ActivityRefused(refusal("profile_mismatch"))


def reader(home: Path) -> ActivityStore:
    """The gated store of ``home`` for reading; raises :class:`ActivityRefused` or :class:`NoHistory`."""
    key = os.path.realpath(home)
    with _lock:
        retry = _retry.get(key)
    if retry is not None and time.monotonic() < retry[0]:
        raise CachedRefusal(refusal(retry[1]))
    found = check_protection(home)
    if found is not None:
        raise ActivityRefused(found)
    path = home.joinpath(*PLUGIN_DATA_SUBPATH, STORE_NAME)
    if not path.is_file():
        raise NoHistory
    if _plaintext(path):
        raise ActivityRefused(refusal("plaintext_store"))
    store = ActivityStore(path, OPENER)
    _check_binding(store, home)
    return store


def forget(home: Path) -> None:
    """Clear the retry delay of ``home``: the next :func:`reader` call tries the store again."""
    with _lock:
        _retry.pop(os.path.realpath(home), None)


def unavailable(home: Path, exc: BaseException) -> None:
    """A surface goes on without history: audit once per process and code, skip the store for a while.

    A :class:`CachedRefusal` keeps the running deadline: calls closer together than :data:`RETRY_AFTER_S`
    must not postpone the next real attempt forever.
    """
    if isinstance(exc, ActivityRefused):
        code = exc.code
    else:
        code = "store_unavailable" if isinstance(exc, OSError) else "internal_error"
        name = type(exc).__name__
        if name not in _logged and len(_logged) < 32:
            _logged.add(name)
            # Content-free: the exception type only, never its message.
            _LOG.warning("mordred activity history unavailable (%s)", name)
    if not isinstance(exc, CachedRefusal):
        with _lock:
            _retry[os.path.realpath(home)] = (time.monotonic() + RETRY_AFTER_S, code)
    audit_history_unavailable(code)
