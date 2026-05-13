"""Tor path — drives the official ``tor`` daemon as a child subprocess.

PR1 scope: rendering, port allocation, bootstrap wait, lifecycle. PR2 will
add the richer control-port liveness probe (``GETINFO circuit-status`` via
``stem`` — TODO §3.1 L300) and wire :func:`start_process` into
:mod:`mordred_hermes.network.runtime`.

Subprocess and socket I/O are factored through injectable callables so
tests can replace them with fakes; production paths use the standard
library defaults.

Bridges / obfs4 / Snowflake are out of scope in v1 (TODO §3.1 L303). The
caller is expected to surface a startup warning on censored networks.
"""

from __future__ import annotations

import selectors
import socket
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from .._exceptions import BringupFailed

PATH_NAME: Final[str] = "tor"
DEFAULT_PORT_CANDIDATES: Final[tuple[int, ...]] = (9050, 9150)
DEFAULT_BOOTSTRAP_TIMEOUT: Final[float] = 30.0
DEFAULT_GRACE_SECONDS: Final[float] = 5.0
BOOTSTRAP_DONE_TOKEN: Final[str] = "Bootstrapped 100%"


class _ProcessLike(Protocol):
    """Subset of :class:`subprocess.Popen` we depend on. Easier to mock."""

    @property
    def stdout(self) -> Iterable[str] | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def poll(self) -> int | None: ...


@dataclass(frozen=True, slots=True)
class TorHandle:
    """Live Tor session. Treat as opaque; only :mod:`network.runtime` should peek."""

    process: _ProcessLike
    socks_port: int
    control_port: int
    data_dir: Path


def render_torrc(*, socks_port: int, control_port: int, data_dir: Path) -> str:
    """Render the torrc fragment we hand to ``tor -f -``.

    Kept minimal on purpose. ``ClientUseIPv6 0`` and friends are layered
    on by Phase 3 PR2 once the wizard collects the policy.json fields.
    """
    return (
        f"SOCKSPort 127.0.0.1:{socks_port}\n"
        f"ControlPort 127.0.0.1:{control_port}\n"
        f"CookieAuthentication 1\n"
        f"DataDirectory {data_dir}\n"
    )


def pick_free_port(
    *,
    candidates: tuple[int, ...] = DEFAULT_PORT_CANDIDATES,
    socket_factory: Callable[..., Any] = socket.socket,
    host: str = "127.0.0.1",
) -> int:
    """Return the first port in ``candidates`` whose ``bind`` succeeds.

    Raises :class:`BringupFailed` if every candidate is busy. The probe
    binds and immediately closes — the kernel may briefly hold the
    port in TIME_WAIT, but the tor daemon's own bind retry tolerates
    the typical 1-2 second window.
    """
    last_err: OSError | None = None
    for port in candidates:
        sock = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((host, port))
        except OSError as e:
            last_err = e
            continue
        finally:
            sock.close()
        return port
    raise BringupFailed(f"all candidate Tor SOCKS ports busy: {candidates} (last error: {last_err})")


ReadLine = Callable[[float], "str | None"]
"""Bounded-deadline line reader contract.

A callable that, given a ``deadline_seconds`` budget, returns:

- ``str`` — a line was read (caller checks for the bootstrap token)
- ``""`` (empty string) — readiness timeout; no line available within budget
- ``None`` — stdout has reached EOF
"""


def _make_default_read_line(stdout: Iterable[str]) -> tuple[ReadLine, Callable[[], None]]:
    """Return ``(read_line, cleanup)`` honoring a per-call deadline.

    For real ``Popen.stdout`` (has ``fileno``) we register the descriptor
    with a :class:`selectors.DefaultSelector` and ``select(timeout=budget)``
    — that's the only way to give ``readline()`` a deadline without
    blocking. For test fakes (lists, generators) the next item is always
    available so we just iterate; the deadline argument is ignored.

    Codex P1 / HIGH-2 fix (2026-05-13). Previously this function
    ``for line in stdout`` blocked indefinitely whenever tor stopped
    writing — that codepath is now gone.
    """
    fileno_attr = getattr(stdout, "fileno", None)
    if callable(fileno_attr):
        sel = selectors.DefaultSelector()
        sel.register(cast(Any, stdout), selectors.EVENT_READ)

        def read_line(deadline_seconds: float) -> str | None:
            events = sel.select(timeout=max(deadline_seconds, 0.0))
            if not events:
                return ""
            line = cast(Any, stdout).readline()
            if not line:
                return None
            return cast(str, line)

        def cleanup() -> None:
            sel.close()

        return read_line, cleanup

    iterator = iter(stdout)

    def read_line_iter(deadline_seconds: float) -> str | None:
        del deadline_seconds  # iterables yield immediately or signal EOF
        try:
            return next(iterator)
        except StopIteration:
            return None

    def cleanup_noop() -> None:
        return None

    return read_line_iter, cleanup_noop


def wait_for_bootstrap(
    process: _ProcessLike,
    *,
    timeout: float = DEFAULT_BOOTSTRAP_TIMEOUT,
    clock: Callable[[], float] = time.monotonic,
    read_line: ReadLine | None = None,
) -> None:
    """Read ``process.stdout`` until ``BOOTSTRAP_DONE_TOKEN`` appears.

    Raises :class:`BringupFailed` if the token is not seen before
    ``timeout`` seconds (per ``clock``) elapse, or if stdout closes
    without producing the token.

    The ``read_line`` callable encapsulates "get next line, honoring a
    per-call deadline". Default reads from ``process.stdout`` with
    :mod:`selectors` so an idle real ``tor`` daemon cannot wedge the
    loop. Tests inject a fake that returns ``""`` (readiness timeout)
    or ``None`` (EOF) without touching real file descriptors.
    """
    cleanup: Callable[[], None] | None = None
    if read_line is None:
        stdout = process.stdout
        if stdout is None:
            raise BringupFailed("tor process has no stdout to tail")
        read_line, cleanup = _make_default_read_line(stdout)

    try:
        deadline = clock() + timeout
        while True:
            remaining = deadline - clock()
            if remaining <= 0:
                raise BringupFailed(f"tor bootstrap timeout after {timeout}s")
            line = read_line(remaining)
            if line is None:
                raise BringupFailed("tor stdout closed before bootstrap completed")
            if line == "":
                continue
            if BOOTSTRAP_DONE_TOKEN in line:
                return
    finally:
        if cleanup is not None:
            cleanup()


def stop(handle: TorHandle, *, grace_seconds: float = DEFAULT_GRACE_SECONDS) -> None:
    """Terminate, wait the grace window, then kill if still alive.

    Mirrors the contract documented in TODO §3.1 L302
    ("``process.terminate()`` + 5s grace + ``kill()``"). Idempotent if
    the process already exited.

    Note on exception types (Codex review P1 / HIGH-1, 2026-05-13):
    real :class:`subprocess.Popen.wait` raises
    :class:`subprocess.TimeoutExpired` (inheriting ``SubprocessError →
    Exception``), *not* the built-in :class:`TimeoutError` (which is an
    ``OSError`` subclass). We must catch the former so the kill
    escalation actually fires in production.
    """
    proc = handle.process
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            return


def health(handle: TorHandle) -> bool:
    """Shallow liveness: subprocess is still running.

    PR2 will replace this with a control-port circuit-status probe once
    the ``stem`` dependency lands. Until then, the network layer trusts
    that a running ``tor`` process is healthy enough for sessions.
    """
    return handle.process.poll() is None


def start_process(
    *,
    binary: str,
    torrc: str,
    popen_factory: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
) -> _ProcessLike:
    """Spawn ``tor -f -`` with the rendered torrc on stdin.

    Production wiring only; tests inject ``popen_factory`` to swap in
    a fake. Kept separate from the higher-level orchestration so the
    per-step behavior is independently testable.
    """
    proc = popen_factory(
        [binary, "-f", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if proc.stdin is not None:
        proc.stdin.write(torrc)
        proc.stdin.close()
    return cast(_ProcessLike, proc)
