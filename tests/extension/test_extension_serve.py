"""Tests for the ``python -m mordred_hermes.extension`` / ``hermes-mordred
extension serve`` launcher (:mod:`mordred_hermes.extension.__main__`).

Kept deliberately light: the WebSocket protocol itself is already covered
end-to-end by ``test_extension_api_server.py``. This file exercises the
launcher's own contract — argparse wiring (both entry forms), the failure
paths (port in use / out of range, missing extra), and one subprocess-based
lifecycle test (start → SIGTERM → clean exit 0) with hard timeouts so it
cannot hang.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import time

import pytest

from mordred_hermes.extension.__main__ import main, serve
from mordred_hermes.wizard.cli import _setup_subparser


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _build_wizard_parser() -> argparse.ArgumentParser:
    """Build an isolated ``hermes mordred`` parser (mirrors
    ``tests/test_wizard_cli.py::_build_parser``)."""
    root = argparse.ArgumentParser(prog="hermes")
    sub = root.add_subparsers(dest="command")
    plugin_parser = sub.add_parser("mordred")
    _setup_subparser(plugin_parser)
    return root


def test_main_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    # NOTE: this cannot prove `--help` works without aiohttp — the package
    # __init__ eagerly imports .api (and thus aiohttp) before __main__ ever
    # runs; the friendly missing-extra path lives in the wizard handler and
    # is covered by test_wizard_extension_serve_missing_extra below.
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    assert "ws://127.0.0.1:7788/ext" in capsys.readouterr().out


def test_wizard_extension_serve_missing_extra(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate the `extension` extra being absent: a None entry in sys.modules
    # makes `from mordred_hermes.extension.__main__ import serve` raise
    # ImportError exactly as an uninstalled aiohttp would.
    import sys

    from mordred_hermes.wizard._cli_parsers import _handle_extension_serve

    monkeypatch.setitem(sys.modules, "mordred_hermes.extension.__main__", None)
    rc = _handle_extension_serve(argparse.Namespace(host="127.0.0.1", port=7788))
    assert rc == 2
    err = capsys.readouterr().err
    assert "extension` extra" in err
    assert "import failed:" in err


def test_serve_rejects_non_loopback_host(capsys: pytest.CaptureFixture[str]) -> None:
    rc = serve(host="0.0.0.0", port=_free_port())
    assert rc == 2
    err = capsys.readouterr().err
    assert "refusing non-loopback" in err


def test_serve_port_in_use_returns_one(capsys: pytest.CaptureFixture[str]) -> None:
    port = _free_port()
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", port))
    blocker.listen(1)
    try:
        rc = serve(port=port)
    finally:
        blocker.close()

    assert rc == 1
    err = capsys.readouterr().err
    assert "already in use" in err
    assert "gateway" in err
    # Cause-neutral: names both plausible listeners rather than assuming a
    # gateway, and gives concrete next steps instead of just diagnosing.
    assert "extension serve" in err
    assert f"lsof -i :{port}" in err
    assert "--port" in err


@pytest.mark.parametrize("bad_port", [0, -1, 99999])
def test_serve_rejects_out_of_range_port(bad_port: int, capsys: pytest.CaptureFixture[str]) -> None:
    # Without this guard, socket.bind() raises OverflowError — a raw
    # traceback instead of the documented one-line error.
    rc = serve(port=bad_port)
    assert rc == 2
    assert "1-65535" in capsys.readouterr().err


def test_serve_sigterm_clean_shutdown(tmp_path) -> None:
    """SIGTERM (systemd / `docker stop`) must exit 0 via server.stop(), like Ctrl+C.

    Also covers the startup banner and shutdown confirmation: this is the
    one lifecycle test that actually runs `serve()` start-to-finish (the
    other tests only exercise failure paths), so it is the only place that
    can observe the banner's ws:// / http:// lines and the final "Stopped."
    line printed after server.stop() completes.
    """
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "mordred_hermes.extension", "--port", str(port)],
        env={**os.environ, "HERMES_HOME": str(tmp_path)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("server did not start listening within 10s")
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    assert proc.returncode == 0, out
    assert f"ws://127.0.0.1:{port}/ext" in out
    assert f"http://127.0.0.1:{port}/" in out
    assert "Press Ctrl+C to stop." in out
    assert "Stopped." in out


def test_resolve_chat_handler_uses_gateway_runtime_when_present() -> None:
    # hermes-agent is a base dependency, so the repo venv always has the
    # gateway/run_agent modules — serve must wire the REAL agent handler,
    # not the stub (the stub silently drops E2E chat on the floor).
    from mordred_hermes.extension.__main__ import _resolve_chat_handler

    assert _resolve_chat_handler() is not None


def test_resolve_chat_handler_falls_back_to_stub_without_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util

    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str, *args: object) -> object:
        if name in ("gateway", "run_agent"):
            return None
        return real_find_spec(name, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    from mordred_hermes.extension.__main__ import _resolve_chat_handler

    assert _resolve_chat_handler() is None


def test_wizard_extension_serve_parses_host_and_port() -> None:
    parser = _build_wizard_parser()
    ns = parser.parse_args(["mordred", "extension", "serve", "--port", "1234"])
    assert ns.port == 1234
    assert ns.host == "127.0.0.1"
    assert callable(ns.func)


def test_wizard_extension_serve_defaults() -> None:
    parser = _build_wizard_parser()
    ns = parser.parse_args(["mordred", "extension", "serve"])
    assert ns.port == 7788
    assert ns.host == "127.0.0.1"
