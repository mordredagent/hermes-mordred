"""Operation-local OS presence authority; never stores decrypted material.

Only trusted host adapters enter ``presence_scope``. An ECDH is eligible only
inside both that host scope and a matching concrete credential read. Wallets,
management calls and CLI code never enter the latter scope.

Separately, a Mordred operation that opens several of its own keys in a row
(``setup`` creating them, ``extension serve`` opening the vault and the
databases) can hold an :func:`operation_window`: one OS prompt then covers up
to :data:`WINDOW_KEYS` of this home's keys for at most the purpose's seconds,
and the window closes (killing the helper child) when the operation ends.
Telegram and mail credential keys are never admitted to a window.
"""

from __future__ import annotations

import atexit
import contextlib
import contextvars
import hashlib
import os
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from weakref import WeakSet

from ._presence_transport import Channel, PresenceChannel
from ._seckey_errors import _OpsError

#: Seconds a window may reuse one prompt, by purpose (the helper caps sessions at 300).
OPERATION_SECONDS: dict[str, int] = {"setup": 300, "startup": 60}
#: Distinct keys one window may open: keyvault, vault, databases, audit log, with room.
WINDOW_KEYS = 8
_WINDOW_PRINCIPAL = "mordred-operation"


def _reuse_seconds(value: object) -> int:
    return value if type(value) is int and 0 <= value <= 300 else 0


#: Left by ``setup`` when it enrolled attended keys: this home's operations may
#: then hold a window. Unattended keys never prompt, so a window would add one.
OPERATION_PRESENCE_MARKER = "operation-presence"


def operation_presence_configured(home: Path) -> bool:
    """Whether setup enrolled attended keys and so opted this home into operation windows."""
    try:
        return stat.S_ISREG((home / "mordred" / OPERATION_PRESENCE_MARKER).lstat().st_mode)
    except OSError:
        return False


def enable_operation_presence(home: Path) -> None:
    """Record that this home's keys are attended (an empty private file)."""
    marker = home / "mordred" / OPERATION_PRESENCE_MARKER
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)


def configured_seconds(home: Path) -> int:
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    try:
        data = YAML(typ="safe").load((home / "config.yaml").read_text("utf-8"))
        return _reuse_seconds(data["plugins"]["mordred_keyvault"]["presence_reuse_seconds"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, YAMLError):
        return 0


@dataclass(frozen=True, eq=False)
class _Scope:
    home: Path
    principal: tuple[str, ...]
    purpose: str
    valid: Callable[[], bool] = field(compare=False, repr=False)
    cancelled: threading.Event = field(default_factory=threading.Event, compare=False, repr=False)

    def active(self) -> bool:
        return not self.cancelled.is_set() and self.valid()


_scope: contextvars.ContextVar[_Scope | None] = contextvars.ContextVar("mordred_presence", default=None)
_credential: contextvars.ContextVar[tuple[Path, str, str] | None] = contextvars.ContextVar(
    "mordred_presence_credential", default=None
)


@contextlib.contextmanager
def presence_scope(
    home: Path, principal: tuple[str, ...], purpose: str, *, valid: Callable[[], bool] = lambda: True
) -> Iterator[None]:
    """Bind a trusted host identity to this operation, including child threads/tasks."""
    scope = _Scope(home.resolve(), principal, purpose, valid)
    _pool.bind_scope(scope)
    token = _scope.set(scope)
    try:
        yield
    except BaseException:
        scope.cancelled.set()
        _pool.revoke(home=scope.home, principal=principal, purpose=purpose)
        raise
    finally:
        _scope.reset(token)


@contextlib.contextmanager
def credential_scope(home: Path, purpose: str, observation: object) -> Iterator[None]:
    """Restrict eligibility to a fresh, checked custody observation (no secrets)."""
    binding = hashlib.sha256(repr(observation).encode()).hexdigest()
    token = _credential.set((home.resolve(), purpose, binding))
    try:
        yield
    except BaseException:
        revoke_current()
        raise
    finally:
        _credential.reset(token)


@dataclass(frozen=True)
class OperationWindow:
    scope: _Scope
    seconds: int
    binding: str
    pid: int


_window: OperationWindow | None = None
_window_lock = threading.Lock()


def open_window(home: Path, purpose: str) -> Callable[[], None]:
    """Open this process's operation window; returns the idempotent closer.

    Only Mordred's own operations call this, and only when the home's keys are
    attended (unattended keys never prompt, so a window would add a prompt).
    """
    global _window
    seconds = OPERATION_SECONDS[purpose]
    scope = _Scope(home.resolve(), (_WINDOW_PRINCIPAL, purpose), purpose, lambda: True)
    window = OperationWindow(scope, seconds, f"operation:{purpose}", os.getpid())
    with _window_lock:
        if _window is not None and _window.pid == os.getpid() and _window.scope.active():
            raise _refused("an operation window is already open")
        _window = window

    def close() -> None:
        global _window
        with _window_lock:
            if _window is window:
                _window = None
        scope.cancelled.set()
        _pool.revoke(home=scope.home, principal=scope.principal, purpose=purpose)

    return close


@contextlib.contextmanager
def operation_window(home: Path, purpose: str) -> Iterator[None]:
    close = open_window(home, purpose)
    try:
        yield
    finally:
        close()


def confirm_window() -> None:
    """Ask for this process's window's Touch ID now, before the operation uses any key.

    An operation that confirms first stops before it has changed anything when
    the prompt is missed or cancelled (raises ``_OpsError``), so it can simply
    run again. A no-op without a window, off macOS, or with a helper that
    cannot confirm ahead (its first key use asks instead).
    """
    window = _window
    if sys.platform != "darwin" or window is None or window.pid != os.getpid() or not window.scope.active():
        return
    from . import _seckey_helper

    binary = _seckey_helper.find_sekey_helper()
    if binary is None:
        return
    try:
        capabilities = _seckey_helper._run_helper(binary, {"cmd": "capabilities"})
    except _OpsError:
        return
    if capabilities.get("presence_confirm") != 1 or capabilities.get("presence_stores") != 1:
        return
    _ensure_monitor()
    response = _pool.exchange(
        window.scope,
        binary,
        None,
        b"",
        b"",
        window.seconds,
        window.binding,
        max_keys=WINDOW_KEYS,
        confirm=True,
        reason=touch_id_reason(window.scope.purpose) if capabilities.get("presence_reason") == 1 else None,
    )
    if response.get("ok") is not True:
        raise _refused("presence was not confirmed")


#: What the Touch ID window says for each purpose (English; :mod:`..i18n` translates).
_REASONS: Final = {
    "credentials": "Read Mordred's Telegram or mail sign-in",
    "setup": "Set up Mordred's keys and encryption",
    "startup": "Open Mordred's vault and databases",
}


def touch_id_reason(purpose: str) -> str:
    """The Touch ID window's text for ``purpose``, in the Mac's language."""
    from .. import i18n

    return i18n.text(f"touchId.{purpose}", _REASONS.get(purpose, _REASONS["credentials"]))


def window_for(tag: bytes) -> OperationWindow | None:
    """The open window admitting ``tag``; never one for a Telegram or mail credential key."""
    window = _window
    if sys.platform != "darwin" or window is None or window.pid != os.getpid() or not window.scope.active():
        return None
    from ._mail_key import KEY_ID as mail_key
    from ._seckey_errors import _application_tag
    from ._telegram_custody import KEY_ID as telegram_key

    if tag in (_application_tag(telegram_key), _application_tag(mail_key)):
        return None
    _ensure_monitor()
    return window


def eligible(tag: bytes) -> tuple[_Scope, int, str] | None:
    scope, credential = _scope.get(), _credential.get()
    if sys.platform != "darwin" or scope is None or credential is None:
        return None
    if credential[:2] != (scope.home, scope.purpose):
        return None
    from ._mail_key import KEY_ID as mail_key
    from ._seckey_errors import _application_tag
    from ._telegram_custody import KEY_ID as telegram_key

    selector = {"telegram": telegram_key, "mail": mail_key}.get(scope.purpose)
    if selector is None or tag != _application_tag(selector):
        return None
    if scope.cancelled.is_set():
        raise _refused("presence operation revoked")
    seconds = configured_seconds(scope.home)
    if not seconds:
        return None
    _ensure_monitor()
    return scope, seconds, credential[2]


def _version(paths: tuple[Path, ...]) -> tuple[object, ...]:
    result: list[object] = []
    for path in paths:
        try:
            st = path.lstat()
            identity = (st.st_dev, st.st_ino, st.st_mode, st.st_uid)
            result.append(
                identity if stat.S_ISDIR(st.st_mode) else (*identity, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            )
        except FileNotFoundError:
            result.append(None)
    return tuple(result)


def _watch_paths(scope: _Scope, binary: str, env: tuple[str, str] | None, tag: bytes | None) -> tuple[Path, ...]:
    if tag is None:
        # A window spans an operation that writes config and creates keys and
        # stores, and its one helper serves every store the operation uses. The
        # helper binds each key to its store and file; here only the home and
        # the helper must stay the same.
        return (scope.home, Path(binary))
    store = Path(env[1]) if env is not None else scope.home / "mordred/keyvault/sekey"
    root = scope.home / "mordred" / scope.purpose
    names = ("credentials.sealed", "credentials.meta.json", "enclave-key.json", "generation", "mail-forget.json")
    return (
        scope.home,
        root,
        Path(binary),
        scope.home / "config.yaml",
        scope.home / "mordred/telegram-forget.json",
        store,
        store / (tag.hex() + ".bin"),
        *(root / name for name in names),
    )


@dataclass
class _Entry:
    scope: _Scope
    binding: str
    channel: PresenceChannel
    seconds: int
    paths: tuple[Path, ...]
    version: tuple[object, ...]
    deadline: float | None = None
    failure: _OpsError | None = None
    pending: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


def _refused(message: str) -> _OpsError:
    return _OpsError(-1, "helper", message)


def _copy_error(error: _OpsError) -> _OpsError:
    # Never store or re-raise an exception carrying decrypt-frame locals.
    return _OpsError(error.status, error.domain, str(error), reason=error.reason)


class _PresencePool:
    def __init__(
        self, *, factory: Callable[..., PresenceChannel] = Channel, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._factory = factory
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: dict[tuple[object, ...], _Entry] = {}
        self._scopes: WeakSet[_Scope] = WeakSet()

    def bind_scope(self, scope: _Scope) -> None:
        with self._lock:
            if not scope.active():
                raise _refused("presence operation revoked")
            if scope in self._scopes:
                return
            for previous in list(self._scopes):
                if previous.principal == scope.principal and previous.home != scope.home:
                    previous.cancelled.set()
            self._scopes.add(scope)
            self.reap()

    @property
    def pending(self) -> int:
        with self._lock:
            return sum(e.pending for e in self._entries.values())

    def _discard(self, key: tuple[object, ...], entry: _Entry, error: _OpsError) -> None:
        # No authentication/I/O lock is acquired here. close() kills the child
        # and wakes a blocked exchange, including its first OS prompt.
        if entry.failure is None:
            entry.failure = _copy_error(error)
        entry.channel.close()
        if self._entries.get(key) is entry:
            self._entries.pop(key)

    def _current(self, entry: _Entry) -> bool:
        try:
            return entry.scope.active() and _version(entry.paths) == entry.version
        except Exception:
            return False

    def reap(self) -> None:
        with self._lock:
            for key, entry in list(self._entries.items()):
                if (
                    not entry.channel.alive()
                    or not self._current(entry)
                    or (entry.deadline is not None and self._clock() >= entry.deadline)
                ):
                    self._discard(key, entry, _refused("presence expired or revoked"))

    def revoke(
        self,
        *,
        home: Path | None = None,
        principal: tuple[str, ...] | None = None,
        purpose: str | None = None,
        windows: bool = True,
    ) -> None:
        with self._lock:
            for key, entry in list(self._entries.items()):
                if not windows and entry.scope.principal[0] == _WINDOW_PRINCIPAL:
                    continue
                if (
                    (home is None or entry.scope.home == home)
                    and (principal is None or entry.scope.principal == principal)
                    and (purpose is None or entry.scope.purpose == purpose)
                ):
                    self._discard(key, entry, _refused("presence revoked"))

    def close(self) -> None:
        self.revoke()

    def _admit(
        self,
        key: tuple[object, ...],
        scope: _Scope,
        binary: str,
        env: tuple[str, str] | None,
        tag: bytes,
        seconds: int,
        binding: str,
        max_keys: int = 1,
        reason: str | None = None,
    ) -> _Entry:
        with self._lock:
            self.bind_scope(scope)
            self.reap()
            if not scope.active():
                raise _refused("presence operation revoked")
            entry = self._entries.get(key)
            if entry is not None and (
                entry.binding != binding or entry.seconds != seconds or not entry.channel.alive()
            ):
                self._discard(key, entry, _refused("presence source changed"))
                entry = None
            if entry is None:
                if len(self._entries) >= 8:
                    raise _refused("presence capacity or authority refused")
                paths = _watch_paths(scope, binary, env, None if max_keys > 1 else tag)
                version = _version(paths)
                options: dict[str, object] = {}
                if max_keys != 1:
                    options.update(max_keys=max_keys, purpose=scope.purpose)
                if reason is not None:
                    options["reason"] = reason
                channel = self._factory(binary, env, seconds, **options)
                entry = _Entry(scope, binding, channel, seconds, paths, version)
                self._entries[key] = entry
            if entry.pending >= 17:  # one active + sixteen waiting requests
                raise _refused("presence queue full")
            entry.pending += 1
        return entry

    def _accept(self, scope: _Scope, entry: _Entry, started: float) -> None:
        # The child owns the authoritative sleep-inclusive deadline, measured
        # from authentication success. The parent also rejects stale replies.
        with self._lock:
            if entry.failure is not None:
                raise _copy_error(entry.failure)
            if not scope.active():
                raise _refused("presence operation revoked")
            if self._clock() - started >= 120:
                raise _refused("presence request timed out")
            if entry.deadline is None:
                entry.deadline = self._clock() + entry.seconds
            if self._clock() >= entry.deadline or not self._current(entry):
                raise _refused("presence expired or revoked during request")

    def exchange(
        self,
        scope: _Scope,
        binary: str,
        env: tuple[str, str] | None,
        tag: bytes,
        peer: bytes,
        seconds: int,
        binding: str,
        *,
        max_keys: int = 1,
        store: str | None = None,
        confirm: bool = False,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """One ECDH through the session; with ``confirm`` (a window only), just its Touch ID."""
        started = self._clock()
        window = max_keys > 1
        if (store is not None or confirm) and not window:
            raise _refused("presence capacity or authority refused")
        # A window's one helper serves several keys in several stores, each
        # request naming its store (``None``: the helper's default store); a
        # credential session serves one key in the store it was started for.
        if window:
            env = None
        key = (os.getpid(), scope.home, scope.principal, scope.purpose, binary, env, "window" if window else tag)
        entry = self._admit(key, scope, binary, env, tag, seconds, binding, max_keys, reason)
        response: dict[str, Any] = {}
        try:
            remaining = 120 - (self._clock() - started)
            if not entry.lock.acquire(timeout=max(0, remaining)):
                raise _refused("presence request timed out")
            try:
                if entry.failure is not None:
                    raise _copy_error(entry.failure)
                if (
                    not scope.active()
                    or not self._current(entry)
                    or (entry.deadline is not None and self._clock() >= entry.deadline)
                ):
                    raise _refused("presence expired or revoked")
                request: dict[str, Any] = {"cmd": "ecdh", "tag_hex": tag.hex(), "peer_pub_hex": peer.hex()}
                if confirm:
                    request = {"cmd": "authenticate"}
                elif store is not None:
                    request["store"] = store
                response = entry.channel.exchange(request, 120 - (self._clock() - started))
                self._accept(scope, entry, started)
                return response
            finally:
                entry.lock.release()
        except BaseException as exc:
            response.clear()
            with self._lock:
                self._discard(key, entry, exc if isinstance(exc, _OpsError) else _refused("presence cancelled"))
                assert entry.failure is not None
                failure = _copy_error(entry.failure)
            if isinstance(exc, _OpsError):
                raise failure from None
            raise
        finally:
            with self._lock:
                entry.pending -= 1


_pool = _PresencePool()


def revoke(
    *,
    home: Path | None = None,
    principal: tuple[str, ...] | None = None,
    purpose: str | None = None,
    windows: bool = True,
) -> None:
    """End matching sessions; ``windows=False`` spares operation windows.

    Creating or deleting a key passes ``windows=False``: setup creates keys
    between the uses its window covers, and the helper already refuses a key
    whose file changed under a session.
    """
    _pool.revoke(home=None if home is None else home.resolve(), principal=principal, purpose=purpose, windows=windows)


def revoke_current() -> None:
    scope = _scope.get()
    if scope is not None:
        scope.cancelled.set()
        revoke(home=scope.home, principal=scope.principal, purpose=scope.purpose)


def _monitor() -> None:
    while True:
        time.sleep(0.1)
        _pool.reap()


# A fork must not inherit live pipes, locks, host scopes or a monitor that no
# longer exists. A fresh pool is created on the child side without locking.
def _after_fork() -> None:
    global _pool
    for entry in _pool._entries.values():
        entry.channel.detach()
    _pool = _PresencePool()
    _scope.set(None)
    _credential.set(None)
    global _window, _window_lock
    _window = None
    _window_lock = threading.Lock()
    global _monitor_pid, _monitor_lock
    _monitor_pid = None
    _monitor_lock = threading.Lock()


_monitor_pid: int | None = None
_monitor_lock = threading.Lock()


def _ensure_monitor() -> None:
    global _monitor_pid
    with _monitor_lock:
        if _monitor_pid != os.getpid():
            _monitor_pid = os.getpid()
            threading.Thread(target=_monitor, name="mordred-presence", daemon=True).start()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
atexit.register(lambda: _pool.close())
