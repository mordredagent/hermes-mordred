"""``extension serve`` shutdown, port release and restart (C11).

Runs the real launcher in a child process on port 7799 (never the production
7788). Windows sends ``CTRL_BREAK_EVENT`` to a new process group (the proactor
loop has no ``add_signal_handler``, so the launcher routes ``SIGBREAK`` through
``signal.signal`` + ``loop.call_soon_threadsafe``); POSIX sends ``SIGTERM``.
Each run must exit 0 within 10 s, leave no child process, free the port, and a
second server must start on the same port immediately, including when an HTTP
keep-alive client and a WebSocket client are still connected at shutdown. The
``signal.signal`` fallback path is also exercised on POSIX by a child whose
loop refuses ``add_signal_handler`` like the Windows proactor loop.

Every child (and, on Windows, the base interpreter a venv ``python.exe``
redirects to) is killed and reaped by the ``servers`` fixture on every exit
path, which then requires 7799 to be free again.
"""

from __future__ import annotations

import asyncio
import errno
import os
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import psutil
import pytest

from mordred_hermes.extension import __main__ as extension_main

PORT = 7799
WINDOWS = sys.platform == "win32"

_FALLBACK_DRIVER = textwrap.dedent(
    """
    import asyncio, signal, sys
    from mordred_hermes.extension import __main__ as launcher

    class ProactorLikeLoop(asyncio.SelectorEventLoop):
        def add_signal_handler(self, *args, **kwargs):
            raise NotImplementedError

    asyncio.new_event_loop = ProactorLikeLoop
    launcher._stop_signals = lambda: (signal.SIGTERM,)
    raise SystemExit(launcher.main(["--port", sys.argv[1]]))
    """
)
_WEBSOCKET_UPGRADE = (
    f"GET /ext HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    f"Origin: http://127.0.0.1:{PORT}\r\n\r\n"
).encode("ascii")


def port_is_free(port: int = PORT) -> bool:
    """No listener, and bindable the way the server binds (asyncio sets SO_REUSEADDR on POSIX only).

    A server-side TIME_WAIT left by a client connected at shutdown therefore
    does not count as busy on POSIX, exactly as it does not stop a restart.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(0.5)
        if client.connect_ex(("127.0.0.1", port)) == 0:
            return False
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if not WINDOWS:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def wait_port_free(timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_is_free():
            return True
        time.sleep(0.1)
    return port_is_free()


@pytest.fixture
def free_7799():
    if not port_is_free():
        pytest.skip("port 7799 is busy on this host (check `lsof -nP -iTCP:7799 -sTCP:LISTEN`)")


def stop_signal() -> int:
    return signal.CTRL_BREAK_EVENT if WINDOWS else signal.SIGTERM  # type: ignore[attr-defined]


def server_process(proc: subprocess.Popen[str]) -> psutil.Process:
    """The interpreter actually serving; a Windows venv ``python.exe`` redirects to a base-interpreter child."""
    root = psutil.Process(proc.pid)
    children = root.children()
    if WINDOWS and len(children) == 1 and children[0].name().lower().startswith("python"):
        return children[0]
    return root


class Servers:
    """Launch servers and guarantee each one is killed and reaped, whatever the test does."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.procs: list[subprocess.Popen[str]] = []
        self.serving: list[psutil.Process] = []

    def launch(self, argv: list[str]) -> subprocess.Popen[str]:
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0  # type: ignore[attr-defined]
        proc = subprocess.Popen(
            [sys.executable, *argv],
            env={**os.environ, "HERMES_HOME": str(self.tmp_path)},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=flags,
        )
        self.procs.append(proc)
        return proc

    def wait_listening(self, proc: subprocess.Popen[str]) -> psutil.Process:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"server exited early: {proc.communicate()[0]}")
            try:
                with socket.create_connection(("127.0.0.1", PORT), timeout=0.2):
                    server = server_process(proc)
                    self.serving.append(server)
                    return server
            except OSError:
                time.sleep(0.05)
        pytest.fail("server did not start listening within 15 s")

    def reap(self) -> None:
        for server in self.serving:
            if server.is_running():
                try:
                    server.kill()
                    server.wait(timeout=10)
                except psutil.Error:
                    pass
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=15)


@pytest.fixture
def servers(free_7799, tmp_path) -> Iterator[Servers]:
    tracker = Servers(tmp_path)
    try:
        yield tracker
    finally:
        tracker.reap()
    assert wait_port_free(), "port 7799 must be free after every server was reaped"


def stop(proc: subprocess.Popen[str], sig: int) -> str:
    proc.send_signal(sig)
    out, _ = proc.communicate(timeout=10)
    return out


def run_once(
    servers: Servers, argv: list[str], sig: int, *, connected: Callable[[], list[socket.socket]] | None = None
) -> str:
    proc = servers.launch(argv)
    server = servers.wait_listening(proc)
    assert server.children(recursive=True) == [], "the server starts no child process"
    clients = connected() if connected is not None else []
    try:
        started = time.monotonic()
        out = stop(proc, sig)
        assert time.monotonic() - started < 10
    finally:
        for client in clients:
            client.close()
    assert proc.returncode == 0, out
    assert "Stopped." in out
    with pytest.raises(psutil.NoSuchProcess):
        server.wait(timeout=10)
        server.status()
    assert port_is_free(), "the port is released when the server exits"
    return out


def connected_clients() -> list[socket.socket]:
    """An HTTP keep-alive client and an open WebSocket on /ext, both still connected at shutdown."""
    http = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    http.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n".encode("ascii"))
    assert http.recv(12).startswith(b"HTTP/1.1")
    websocket = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    websocket.sendall(_WEBSOCKET_UPGRADE)
    assert websocket.recv(12).startswith(b"HTTP/1.1 101"), "the WebSocket upgrade was accepted"
    return [http, websocket]


ARGV = ["-m", "mordred_hermes.extension", "--port", str(PORT)]


def test_serve_stops_releases_the_port_and_restarts_on_7799(servers):
    first = run_once(servers, ARGV, stop_signal())
    assert f"ws://127.0.0.1:{PORT}/ext" in first
    second = run_once(servers, ARGV, stop_signal())  # immediately, on the same port
    assert f"ws://127.0.0.1:{PORT}/ext" in second


def test_serve_stops_within_bound_with_clients_connected_and_restarts(servers):
    run_once(servers, ARGV, stop_signal(), connected=connected_clients)
    run_once(servers, ARGV, stop_signal(), connected=connected_clients)  # same port, right away


def test_a_failure_before_stop_still_reaps_the_server(servers):
    proc = servers.launch(ARGV)
    server = servers.wait_listening(proc)
    servers.reap()  # what the fixture does after any assertion failure
    assert proc.poll() is not None and not server.is_running()
    assert wait_port_free()


@pytest.mark.skipif(WINDOWS, reason="Ctrl-C cannot be delivered to a separate console process group in CI")
def test_serve_ctrl_c_takes_the_keyboard_interrupt_path(servers):
    run_once(servers, ARGV, signal.SIGINT)


@pytest.mark.skipif(WINDOWS, reason="Windows runs the real proactor path in the 7799 test")
def test_signal_signal_fallback_stops_cleanly_without_add_signal_handler(servers, tmp_path):
    driver = tmp_path / "driver.py"
    driver.write_text(_FALLBACK_DRIVER, encoding="utf-8")
    run_once(servers, [str(driver), str(PORT)], signal.SIGTERM)


def test_stop_handler_wakes_the_loop_from_another_thread():
    loop = asyncio.new_event_loop()
    try:
        stop_event = asyncio.Event()
        handler = extension_main._threadsafe_stop(loop, stop_event)
        timer = threading.Timer(0.1, handler, args=(signal.SIGTERM, None))
        timer.start()
        started = time.monotonic()
        loop.run_until_complete(asyncio.wait_for(stop_event.wait(), timeout=5))
        assert time.monotonic() - started < 5
        timer.join()
    finally:
        loop.close()
    # A late console event after the loop closed is ignored, never a traceback.
    handler(signal.SIGTERM, None)


def test_windows_stop_handlers_use_signal_signal_and_are_restored(monkeypatch):
    installed: dict[int, object] = {}
    sentinel = object()
    fake_break = 21

    def fake_signal(signum, handler):
        previous = installed.get(signum, sentinel)
        installed[signum] = handler
        return previous

    monkeypatch.setattr(extension_main.signal, "signal", fake_signal)
    monkeypatch.setattr(extension_main, "_stop_signals", lambda: (fake_break,))

    class ProactorLike(asyncio.SelectorEventLoop):
        def add_signal_handler(self, *args, **kwargs):
            raise NotImplementedError

    loop = ProactorLike()
    try:
        stop_event = asyncio.Event()
        restore = extension_main._install_stop_handlers(loop, stop_event)
        assert callable(installed[fake_break])
        installed[fake_break](fake_break, None)  # type: ignore[operator]
        loop.run_until_complete(asyncio.wait_for(stop_event.wait(), timeout=5))
        restore()
        assert installed[fake_break] is sentinel
    finally:
        loop.close()


@pytest.mark.parametrize(
    ("platform", "code", "classification", "hint"),
    [
        ("darwin", errno.EADDRINUSE, "(port-in-use)", f"lsof -i :{PORT}"),
        ("linux", errno.EADDRINUSE, "(port-in-use)", f"lsof -i :{PORT}"),
        ("win32", 10048, "(port-in-use)", f"Get-NetTCPConnection -LocalPort {PORT} -State Listen"),
        ("win32", 10013, "(port-forbidden)", "excludedportrange"),
        ("linux", errno.EACCES, "(port-forbidden)", "--port"),
        ("linux", errno.EADDRNOTAVAIL, "(bind-failed)", "127.0.0.1"),
    ],
)
def test_bind_failures_are_classified(platform, code, classification, hint):
    message = extension_main._bind_failure(OSError(code, "bind refused"), "127.0.0.1", PORT, platform=platform)
    assert classification in message and hint in message
    assert "--port" in message
    assert "no other port is tried" in message.lower()


def test_busy_7799_refuses_without_falling_back(free_7799, capsys):
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", PORT))
    blocker.listen(1)
    try:
        assert extension_main.serve(port=PORT) == 1
    finally:
        blocker.close()
    captured = capsys.readouterr()
    assert "(port-in-use)" in captured.err and "no other port is tried" in captured.err.lower()
    assert "WebSocket:" not in captured.out, "nothing was served on another port"
