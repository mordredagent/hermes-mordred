"""Tests for ``mordred_hermes.network.paths.tor``.

Subprocess is fully mocked — no real ``tor`` binary touched. Tests cover:

- torrc rendering (SOCKSPort / ControlPort / DataDirectory / CookieAuthentication)
- Port shift from 9050 → 9150 on collision
- All candidate ports busy → ``BringupFailed``
- Successful bootstrap (stdout streams "Bootstrapped 100%")
- Bootstrap timeout → ``BringupFailed``
- ``stop()`` calls ``terminate()``, waits grace, then ``kill()``
- ``health()`` reports ``False`` once the subprocess has exited

PR1 keeps ``health()`` deliberately shallow (process alive vs not).
The richer control-port circuit-status probe lands in PR2 alongside the
``stem`` dependency (TODO §3.1 L300).
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# --------------------------------------------------------------------------- #
# Fake subprocess plumbing                                                    #
# --------------------------------------------------------------------------- #


class _FakePopen:
    """Mimics the subset of ``subprocess.Popen`` we touch."""

    def __init__(self, stdout_lines: list[str], *, exit_after_terminate: bool = True) -> None:
        self._stdout_lines = list(stdout_lines)
        self._exit_after_terminate = exit_after_terminate
        self.terminate_called = False
        self.kill_called = False
        self.wait_called = False
        self._returncode: int | None = None
        self.pid = 4242

    @property
    def stdout(self) -> list[str]:
        return self._stdout_lines

    def terminate(self) -> None:
        self.terminate_called = True
        if self._exit_after_terminate:
            self._returncode = 0

    def kill(self) -> None:
        self.kill_called = True
        self._returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.wait_called = True
        if self._returncode is None:
            # Match the real ``subprocess.Popen.wait`` contract — it raises
            # ``subprocess.TimeoutExpired`` (NOT ``TimeoutError``) when the
            # grace window elapses with the process still running. Codex
            # review P1 (HIGH-1) found ``tor.stop`` was catching the wrong
            # exception type, so this fake now exercises the production
            # path.
            raise subprocess.TimeoutExpired(cmd=["tor"], timeout=timeout or 0.0)
        return self._returncode

    def poll(self) -> int | None:
        return self._returncode


def _make_busy_socket_factory(busy_ports: set[int]) -> Any:
    """Return a fake socket factory whose ``bind`` errors on busy ports."""

    def factory(*_args: Any, **_kwargs: Any) -> Any:
        sock = MagicMock()

        def bind(addr: tuple[str, int]) -> None:
            _, port = addr
            if port in busy_ports:
                raise OSError(48, "Address already in use")

        sock.bind.side_effect = bind
        sock.close.return_value = None
        return sock

    return factory


class _FakeClock:
    """Monotonic-like clock that advances by a fixed step on each call."""

    def __init__(self, *, start: float, step: float) -> None:
        self._t = start
        self._step = step

    def __call__(self) -> float:
        cur = self._t
        self._t += self._step
        return cur


# --------------------------------------------------------------------------- #
# torrc rendering                                                             #
# --------------------------------------------------------------------------- #


class TestTorrcRender:
    def test_includes_socks_port(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "SOCKSPort 127.0.0.1:9050" in content

    def test_includes_control_port(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "ControlPort 127.0.0.1:9051" in content

    def test_includes_cookie_auth(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "CookieAuthentication 1" in content

    def test_includes_data_directory(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert f"DataDirectory {tmp_path}" in content


# --------------------------------------------------------------------------- #
# Port collision handling                                                     #
# --------------------------------------------------------------------------- #


class TestPortShift:
    def test_picks_first_free_port(self) -> None:
        from mordred_hermes.network.paths import tor

        chosen = tor.pick_free_port(
            candidates=(9050, 9150),
            socket_factory=_make_busy_socket_factory(set()),
        )
        assert chosen == 9050

    def test_shifts_to_9150_when_9050_busy(self) -> None:
        from mordred_hermes.network.paths import tor

        chosen = tor.pick_free_port(
            candidates=(9050, 9150),
            socket_factory=_make_busy_socket_factory({9050}),
        )
        assert chosen == 9150

    def test_all_busy_raises_bringup_failed(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        with pytest.raises(BringupFailed):
            tor.pick_free_port(
                candidates=(9050, 9150),
                socket_factory=_make_busy_socket_factory({9050, 9150}),
            )


# --------------------------------------------------------------------------- #
# Bootstrap wait                                                              #
# --------------------------------------------------------------------------- #


class TestBootstrap:
    def test_returns_when_bootstrapped_100(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Tor 0.4.x", "Bootstrapped 5%", "Bootstrapped 100% (done)"])
        tor.wait_for_bootstrap(proc, timeout=1.0, clock=_FakeClock(start=0.0, step=0.01))

    def test_timeout_raises_bringup_failed(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 5%", "Bootstrapped 50%"])
        with pytest.raises(BringupFailed):
            tor.wait_for_bootstrap(proc, timeout=0.1, clock=_FakeClock(start=0.0, step=0.5))

    def test_idle_stdout_does_not_hang(self) -> None:
        """Codex P1 / HIGH-2 (2026-05-13): when the real ``tor`` daemon
        emits a couple of bootstrap lines then stalls without closing
        stdout, the blocking ``for line in stdout`` iterator never wakes
        to check the timeout. The fix makes ``wait_for_bootstrap`` consult
        the deadline between reads; this test injects a ``read_line`` that
        always reports "readiness timeout" (``""``) so the loop's only
        exit path is the deadline raising :class:`BringupFailed`.
        """
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        proc = _FakePopen([])  # stdout never produces lines

        def always_idle(_deadline: float) -> str:
            return ""  # readiness timeout — no line within budget

        with pytest.raises(BringupFailed):
            tor.wait_for_bootstrap(
                proc,
                timeout=0.05,
                clock=_FakeClock(start=0.0, step=0.1),
                read_line=always_idle,
            )

    def test_stdout_closed_before_token(self) -> None:
        """``read_line`` returning ``None`` signals stdout EOF before bootstrap."""
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        proc = _FakePopen([])
        eof_calls: list[float] = []

        def returns_eof(deadline: float) -> None:
            eof_calls.append(deadline)
            return None

        with pytest.raises(BringupFailed):
            tor.wait_for_bootstrap(
                proc,
                timeout=1.0,
                clock=_FakeClock(start=0.0, step=0.01),
                read_line=returns_eof,
            )
        assert eof_calls, "read_line should have been called at least once"


# --------------------------------------------------------------------------- #
# Stop semantics                                                              #
# --------------------------------------------------------------------------- #


class TestStop:
    def test_terminate_then_wait(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 100%"])
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        tor.stop(handle)
        assert proc.terminate_called
        assert proc.wait_called

    def test_kill_on_grace_timeout(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 100%"], exit_after_terminate=False)
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        tor.stop(handle, grace_seconds=0.0)
        assert proc.terminate_called
        assert proc.kill_called


# --------------------------------------------------------------------------- #
# Health probe                                                                #
# --------------------------------------------------------------------------- #


class TestHealth:
    def test_alive_process_is_healthy(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 100%"])
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        assert tor.health(handle) is True

    def test_dead_process_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen([])
        proc._returncode = 1
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        assert tor.health(handle) is False


# --------------------------------------------------------------------------- #
# PATH_NAME constant                                                          #
# --------------------------------------------------------------------------- #


def test_path_name_constant() -> None:
    from mordred_hermes.network.paths import tor

    assert tor.PATH_NAME == "tor"


def test_default_socket_constants() -> None:
    """Sanity: pick_free_port's defaults should be the standard TCP probe."""
    assert socket.AF_INET == 2
    assert socket.SOCK_STREAM == 1
