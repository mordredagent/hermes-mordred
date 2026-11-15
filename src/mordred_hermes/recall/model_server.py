"""The headline model's server, started by Hermes when the model has work and stopped once idle.

The headline model (:mod:`.headlines`) only writes stored lines and answers
membership questions in the background; no search waits for it. A large
model held in memory all day for that is wasteful, so with
``MORDRED_RECALL_LLM_COMMAND`` set Hermes runs the server itself:

- the first request of a pass starts it (or uses one already answering) and
  waits until ``GET <base>/models`` answers;
- after each updater pass, a server Hermes started and has not used for
  ``MORDRED_RECALL_LLM_IDLE_SECONDS`` (default 300) is stopped;
- Hermes stopping stops it too.

The command is split like a shell would (:func:`shlex.split`) but run without
a shell, its output appended to ``<home>/logs/recall-model.log``. Its pid is
kept in ``<home>/run/recall-model.pid``, so a server left running by a Hermes
that was killed is recognised (same command line) and stopped once idle,
instead of being taken for one the user runs. A server Hermes did not start
is used but never stopped.

Unset, the endpoint is expected to be running, as before.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import shlex
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final

_log = logging.getLogger(__name__)

COMMAND_ENV: Final = "MORDRED_RECALL_LLM_COMMAND"
IDLE_ENV: Final = "MORDRED_RECALL_LLM_IDLE_SECONDS"
DEFAULT_IDLE_SECONDS: Final = 300.0
#: Loading a large model from disk can take minutes.
START_TIMEOUT_SECONDS: Final = 300.0
STOP_TIMEOUT_SECONDS: Final = 30.0
_POLL_SECONDS: Final = 1.0

Probe = Callable[[str], bool]


def command_from_env(environ: dict[str, str] | None = None) -> list[str] | None:
    """The server's command line, ``None`` when Hermes is not to run it."""
    env = os.environ if environ is None else environ
    raw = env.get(COMMAND_ENV, "").strip()
    if not raw:
        return None
    try:
        argv = shlex.split(raw)
    except ValueError:
        return None
    return argv or None


def idle_from_env(environ: dict[str, str] | None = None) -> float:
    env = os.environ if environ is None else environ
    try:
        value = float(env.get(IDLE_ENV, "") or DEFAULT_IDLE_SECONDS)
    except ValueError:
        return DEFAULT_IDLE_SECONDS
    return value if value > 0 else DEFAULT_IDLE_SECONDS


def launchable(argv: Sequence[str]) -> bool:
    """Whether the command's program exists (a path, or a name on ``PATH``)."""
    program = argv[0]
    if os.sep in program:
        return os.access(program, os.X_OK)
    return shutil.which(program) is not None


def _default_probe(base_url: str) -> bool:
    from ..extension.health import probe_models

    return probe_models(base_url)


def _command_of(pid: int) -> str | None:
    try:
        out = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def _send_signal(pid: int, sig: int, group: bool) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        if group:
            os.killpg(pid, sig)
        else:
            os.kill(pid, sig)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class OnDemandServer:
    """Starts ``argv`` when :meth:`ensure` finds nothing answering, stops it when idle."""

    def __init__(
        self,
        argv: Sequence[str],
        base_url: str,
        *,
        home: Path,
        idle_s: float = DEFAULT_IDLE_SECONDS,
        start_timeout_s: float = START_TIMEOUT_SECONDS,
        probe: Probe | None = None,
        popen: Callable[..., Any] = subprocess.Popen,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        command_of: Callable[[int], str | None] = _command_of,
        send_signal: Callable[[int, int, bool], None] = _send_signal,
        alive: Callable[[int], bool] = _alive,
        stop_at_exit: bool = True,
    ) -> None:
        self.argv = list(argv)
        self.base_url = base_url
        self.idle_s = idle_s
        self._start_timeout = start_timeout_s
        self._probe = probe or _default_probe
        self._popen = popen
        self._clock = clock
        self._sleep = sleep
        self._command_of = command_of
        self._signal = send_signal
        self._alive = alive
        self._log_path = home / "logs" / "recall-model.log"
        self._pid_path = home / "run" / "recall-model.pid"
        self._lock = threading.Lock()
        self._proc: Any = None
        self._pid: int | None = None  # a server we started (or adopted from a killed Hermes)
        self._ready = False
        self._busy = 0
        self._last_used = clock()
        if stop_at_exit:
            atexit.register(self.stop)

    @property
    def owned(self) -> bool:
        return self._pid is not None

    def ensure(self) -> bool:
        """A server answering at the endpoint, started (and waited for) when none is; ``False`` if none came up."""
        with self._lock:
            self._last_used = self._clock()
            if self._ready and self._running():
                return True
            self._ready = False
            if self._probe(self.base_url):
                self._adopt()
                self._ready = True
                return True
            if not self._running():
                self._start()
            return self._wait_ready()

    def using(self) -> contextlib.AbstractContextManager[bool]:
        """``with server.using() as up:`` around one request, so an idle stop never cuts it."""
        return _Using(self)

    def release_if_idle(self) -> bool:
        """Stop a server Hermes runs once nothing has used it for ``idle_s``; whether it was stopped."""
        with self._lock:
            if not self.owned or self._busy or self._clock() - self._last_used < self.idle_s:
                return False
            _log.info("recall model: idle for %ds, stopping it", int(self._clock() - self._last_used))
            self._stop_locked()
            return True

    def stop(self) -> None:
        """Stop a server Hermes runs. Never waits long for the lock (a start may hold it while loading)."""
        if self._lock.acquire(timeout=5):
            try:
                if self.owned:
                    self._stop_locked()
            finally:
                self._lock.release()
        elif self._pid is not None:
            self._signal(self._pid, signal.SIGTERM, self._proc is not None)

    # -- internals ---------------------------------------------------------

    def _running(self) -> bool:
        if self._proc is not None:
            return bool(self._proc.poll() is None)
        return self._pid is not None and self._alive(self._pid)

    def _start(self) -> None:
        if not launchable(self.argv):
            _log.info("recall model: command not found, not started")
            return
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._pid_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._log_path, "ab") as log:
            self._proc = self._popen(
                self.argv,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
            )
        self._pid = int(self._proc.pid)
        self._pid_path.write_text(f"{self._pid}\n")
        _log.info("recall model: started (pid %d), waiting for it to load", self._pid)

    def _wait_ready(self) -> bool:
        if not self._running():
            return False
        started = self._clock()
        while self._clock() - started < self._start_timeout:
            if self._probe(self.base_url):
                self._ready = True
                self._last_used = self._clock()
                _log.info("recall model: ready after %ds", int(self._clock() - started))
                return True
            if not self._running():
                _log.info("recall model: exited while loading (see %s)", self._log_path.name)
                self._forget()
                return False
            self._sleep(_POLL_SECONDS)
        _log.info("recall model: not ready after %ds, stopping it", int(self._start_timeout))
        self._stop_locked()
        return False

    def _adopt(self) -> None:
        """A server already answering is ours when the pid file names a live process with our command line."""
        if self.owned:
            return
        try:
            pid = int(self._pid_path.read_text().strip())
        except (OSError, ValueError):
            return
        if self._alive(pid) and self._command_of(pid) == shlex.join(self.argv):
            self._pid = pid
            _log.info("recall model: using the server a previous Hermes started (pid %d)", pid)

    def _stop_locked(self) -> None:
        pid = self._pid
        if pid is None:
            return
        # A server we started leads its own process group (start_new_session): stop the whole group.
        self._signal(pid, signal.SIGTERM, self._proc is not None)
        deadline = self._clock() + STOP_TIMEOUT_SECONDS
        while self._running() and self._clock() < deadline:
            self._sleep(0.2)
        if self._running():
            self._signal(pid, signal.SIGKILL, self._proc is not None)
        _log.info("recall model: stopped (pid %d)", pid)
        self._forget()

    def _forget(self) -> None:
        self._proc = None
        self._pid = None
        self._ready = False
        with contextlib.suppress(OSError):
            self._pid_path.unlink()


class _Using:
    def __init__(self, server: OnDemandServer) -> None:
        self._server = server

    def __enter__(self) -> bool:
        up = self._server.ensure()
        with self._server._lock:
            self._server._busy += 1
        return up

    def __exit__(self, *_exc: object) -> None:
        with self._server._lock:
            self._server._busy -= 1
            self._server._last_used = self._server._clock()
