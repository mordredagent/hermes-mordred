"""``extension serve`` shutdown, port release and restart (C11).

Runs the real launcher in a child process on port 7799 (never the production
7788). Windows sends ``CTRL_BREAK_EVENT`` to a new process group (the proactor
loop has no ``add_signal_handler``, so the launcher routes ``SIGBREAK`` through
``signal.signal`` + ``loop.call_soon_threadsafe``); POSIX sends ``SIGTERM``.
Each run must exit 0 within 10 s, leave no child process, free the port, and a
second server must start on the same port immediately. The ``signal.signal``
fallback path is also exercised on POSIX by a child whose loop refuses
``add_signal_handler`` like the Windows proactor loop.
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


def port_is_free(port: int = PORT) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


@pytest.fixture
def free_7799():
    if not port_is_free():
        pytest.skip("port 7799 is busy on this host (check `lsof -nP -iTCP:7799 -sTCP:LISTEN`)")


def launch(tmp_path: Path, argv: list[str]) -> subprocess.Popen[str]:
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0  # type: ignore[attr-defined]
    return subprocess.Popen(
        [sys.executable, *argv],
        env={**os.environ, "HERMES_HOME": str(tmp_path)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=flags,
    )


def wait_listening(proc: subprocess.Popen[str], port: int = PORT) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"server exited early: {proc.communicate()[0]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    pytest.fail("server did not start listening within 15 s")


def stop(proc: subprocess.Popen[str], sig: int) -> str:
    try:
        proc.send_signal(sig)
        out, _ = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    return out


def stop_signal() -> int:
    return signal.CTRL_BREAK_EVENT if WINDOWS else signal.SIGTERM  # type: ignore[attr-defined]


def server_process(proc: subprocess.Popen[str]) -> psutil.Process:
    """The interpreter actually serving; a Windows venv ``python.exe`` redirects to a base-interpreter child."""
    root = psutil.Process(proc.pid)
    children = root.children()
    if WINDOWS and len(children) == 1 and children[0].name().lower().startswith("python"):
        return children[0]
    return root


def run_once(tmp_path: Path, argv: list[str], sig: int) -> str:
    proc = launch(tmp_path, argv)
    wait_listening(proc)
    server = server_process(proc)
    assert server.children(recursive=True) == [], "the server starts no child process"
    out = stop(proc, sig)
    assert proc.returncode == 0, out
    assert "Stopped." in out
    with pytest.raises(psutil.NoSuchProcess):
        server.wait(timeout=10)
        server.status()
    assert port_is_free(), "the port is released when the server exits"
    return out


def test_serve_stops_releases_the_port_and_restarts_on_7799(free_7799, tmp_path):
    argv = ["-m", "mordred_hermes.extension", "--port", str(PORT)]
    first = run_once(tmp_path, argv, stop_signal())
    assert f"ws://127.0.0.1:{PORT}/ext" in first
    second = run_once(tmp_path, argv, stop_signal())  # immediately, on the same port
    assert f"ws://127.0.0.1:{PORT}/ext" in second


@pytest.mark.skipif(WINDOWS, reason="Ctrl-C cannot be delivered to a separate console process group in CI")
def test_serve_ctrl_c_takes_the_keyboard_interrupt_path(free_7799, tmp_path):
    run_once(tmp_path, ["-m", "mordred_hermes.extension", "--port", str(PORT)], signal.SIGINT)


@pytest.mark.skipif(WINDOWS, reason="Windows runs the real proactor path in the 7799 test")
def test_signal_signal_fallback_stops_cleanly_without_add_signal_handler(free_7799, tmp_path):
    driver = tmp_path / "driver.py"
    driver.write_text(_FALLBACK_DRIVER, encoding="utf-8")
    run_once(tmp_path, [str(driver), str(PORT)], signal.SIGTERM)


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
