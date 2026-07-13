"""``python -m mordred_hermes.extension`` — run the browser-extension
WebSocket server (:mod:`mordred_hermes.extension.api`) in the foreground.

Serves ``ws://127.0.0.1:7788/ext`` (SPEC.ja.md §6). This is the one-command
launcher for operators who want the extension bridge running without a full
Hermes gateway process; ``hermes-mordred extension serve``
(``wizard/_cli_parsers.py``) wires the same :func:`serve` into the wizard CLI.

aiohttp is the server's only extra dependency (the ``extension`` optional-
dependencies group in ``pyproject.toml``). :mod:`.api` is imported lazily
inside :func:`serve` as defense in depth, but ``python -m`` cannot avoid the
package ``__init__`` — which eagerly imports :mod:`.api` and thus aiohttp —
so with the extra missing this module never loads; the friendly install hint
for that case lives in the wizard's ``extension serve`` handler
(``wizard/_cli_parsers.py:_handle_extension_serve``).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import errno
import logging
import signal
import sys
from typing import Any

# Mirrors mordred_hermes.extension.api.DEFAULT_HOST / DEFAULT_PORT (protocol
# constants, SPEC.ja.md §6). Hardcoded rather than imported at module scope so
# importing *this* module never pulls in aiohttp — see the module docstring.
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 7788


def _resolve_chat_handler() -> Any:
    """Return the real gateway-agent chat handler when the Hermes runtime is
    importable, else ``None`` (server falls back to its built-in stub).

    The PyPI ``hermes-agent`` package ships ``gateway`` / ``run_agent`` as
    top-level modules, so any correctly-installed plugin environment gets the
    real handler — the stub remains only for exotic installs without the
    runtime. ``find_spec`` probes without importing; the heavy imports happen
    lazily inside the handler on the first chat turn.
    """
    import importlib.util

    try:
        if importlib.util.find_spec("gateway") is None or importlib.util.find_spec("run_agent") is None:
            return None
        from .chat import make_gateway_chat_handler

        return make_gateway_chat_handler(None)
    except Exception as exc:
        # A broken runtime should degrade to the stub, but never silently:
        # without this line a real bug in chat.py would masquerade as a
        # missing-runtime install.
        logging.getLogger(__name__).warning("gateway chat handler unavailable, falling back to stub: %s", exc)
        return None


def serve(host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT) -> int:
    """Start the extension WebSocket server and block until interrupted.

    Returns a process exit code (never raises for the documented failure
    modes): ``2`` if the ``extension`` extra (aiohttp) isn't installed or
    ``port`` is out of range, ``1`` if binding ``host``:``port`` failed —
    already bound (most likely a running Hermes gateway hosting the
    extension API), unresolvable host, or insufficient privileges — else
    ``0`` after a clean shutdown on Ctrl+C or SIGTERM.
    """
    try:
        from .api import ExtensionAPIServer
    except ImportError:
        print(
            "error: the extension server needs the `extension` extra (aiohttp). "
            'Install it with `pip install "mordred-hermes[extension]"` or, inside '
            "this repo, `uv sync --extra extension`.",
            file=sys.stderr,
        )
        return 2

    # argparse's type=int does no range check; out-of-range values would
    # otherwise surface as an OverflowError traceback from socket.bind().
    if not 0 < port <= 65535:
        print(f"error: port must be 1-65535 (got {port}).", file=sys.stderr)
        return 2

    # The wire protocol is designed localhost-only and carries no TLS (SPEC
    # §6; the Origin check is the only transport-level gate) — binding a
    # routable interface exposes pairing/auth attempts to the whole network.
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"warning: binding {host} exposes the extension API beyond localhost — "
            "the protocol is localhost-only by design and has no TLS.",
            file=sys.stderr,
        )

    # INFO so ExtensionAPIServer.start()'s "Mordred extension API on ws://..."
    # line reaches the console; this is a foreground/CLI launcher, not a
    # library import, so configuring the root logger here is appropriate.
    logging.basicConfig(level=logging.INFO)

    chat_handler = _resolve_chat_handler()
    logging.getLogger(__name__).info(
        "chat handler: %s",
        "gateway agent (Hermes runtime found)" if chat_handler else "stub (Hermes runtime not importable)",
    )
    server = ExtensionAPIServer(host=host, port=port, chat_handler=chat_handler)
    # A manually managed loop (vs. asyncio.run) so the EADDRINUSE / Ctrl+C
    # paths below can each call `server.stop()` deterministically on the same
    # loop before it closes, instead of relying on asyncio.run()'s implicit
    # task-cancellation cleanup.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # systemd / `docker stop` / plain `kill` send SIGTERM; route it through
        # the same clean shutdown as Ctrl+C so supervisors see exit 0 rather
        # than an abrupt signal death. Installed BEFORE binding: a supervisor
        # (or the SIGTERM test) may signal as soon as the port accepts, which
        # happens inside server.start() — the handler must already exist then.
        stop = asyncio.Event()
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(signal.SIGTERM, stop.set)
        try:
            loop.run_until_complete(server.start())
        except OSError as exc:
            # gaierror (bad --host) and PermissionError (privileged port) are
            # OSError subclasses — every bind failure gets the same one-line
            # error UX instead of a traceback.
            loop.run_until_complete(server.stop())
            if exc.errno == errno.EADDRINUSE:
                print(
                    f"error: port {port} is already in use — a running Hermes "
                    "gateway may already be hosting the extension API.",
                    file=sys.stderr,
                )
            else:
                print(f"error: could not bind {host}:{port} — {exc}", file=sys.stderr)
            return 1
        try:
            loop.run_until_complete(stop.wait())
        except KeyboardInterrupt:
            pass
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.remove_signal_handler(signal.SIGTERM)
            loop.run_until_complete(server.stop())
        return 0
    finally:
        loop.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m mordred_hermes.extension",
        description="Run the Mordred browser-extension WebSocket server (ws://127.0.0.1:7788/ext) in the foreground.",
    )
    parser.add_argument(
        "--host",
        default=_DEFAULT_HOST,
        help=f"Bind host (default: {_DEFAULT_HOST} — non-loopback exposes the no-TLS API to your network)",
    )
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT, help=f"Bind port (default: {_DEFAULT_PORT})")
    args = parser.parse_args(argv)
    return serve(host=args.host, port=args.port)


if __name__ == "__main__":
    raise SystemExit(main())
