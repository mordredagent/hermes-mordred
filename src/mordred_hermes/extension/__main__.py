"""``python -m mordred_hermes.extension`` — run the browser-extension
WebSocket server (:mod:`mordred_hermes.extension.api`) in the foreground.

Serves ``ws://127.0.0.1:7788/ext`` (SPEC.ja.md §6). This is the one-command
launcher for operators who want the extension bridge running without a full
Hermes gateway process; ``hermes-mordred extension serve``
(``wizard/_cli_parsers.py``) wires the same :func:`serve` into the wizard CLI.

aiohttp is the server's only extra dependency (the ``extension`` optional-
dependencies group in ``pyproject.toml``). The extension package and this
launcher are both lazy, so help and argument parsing work without aiohttp.
:func:`serve` checks that dependency immediately before importing :mod:`.api`
and prints the install hint when it is absent.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import errno
import importlib
import logging
import signal
import sys
from typing import TYPE_CHECKING, Any

from .. import _term

if TYPE_CHECKING:
    from .api import ExtensionAPIServer

# Mirrors mordred_hermes.extension.api.DEFAULT_HOST / DEFAULT_PORT (protocol
# constants, SPEC.ja.md §6). Hardcoded rather than imported at module scope so
# importing *this* module never pulls in aiohttp — see the module docstring.
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 7788


def _load_vault_managed_environment() -> int:
    """Install the same sealed ``.env`` shim used by plugin discovery.

    The standalone launcher does not run ``mordred_keyvault.register()``.  A
    manifest pre-check keeps an extension-only install free of macOS Keychain
    dependencies when no vault exists, while any on-disk vault state takes the
    normal fail-closed runtime path.
    """

    from ..keyvault._identity import default_vault_root

    if not any(default_vault_root().glob("manifest.*.mvmf")):
        return 0
    from ..keyvault._runtime_env import install_vault_env_decrypt

    return install_vault_env_decrypt()


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
    already bound (either a stale ``extension serve`` from an earlier
    session or a running Hermes gateway already hosting the extension API),
    unresolvable host, or insufficient privileges — else ``0`` after a clean
    shutdown on Ctrl+C or SIGTERM.
    """
    try:
        importlib.import_module("aiohttp")
    except ModuleNotFoundError as exc:
        # Catch only the absent optional dependency itself. A missing aiohttp
        # subdependency, or an ImportError in this launcher's own API module,
        # is a genuine broken installation/code path and must remain visible.
        if exc.name != "aiohttp":
            raise
        print(
            "error: the extension server needs the `extension` extra (aiohttp). "
            'Install it with `pip install "hermes-mordred[extension]"` or, inside '
            "this repo, `uv sync --extra extension`.",
            file=sys.stderr,
        )
        return 2

    from .api import ExtensionAPIServer, _is_loopback_host

    # argparse's type=int does no range check; out-of-range values would
    # otherwise surface as an OverflowError traceback from socket.bind().
    if not 0 < port <= 65535:
        print(f"error: port must be 1-65535 (got {port}).", file=sys.stderr)
        return 2

    # The wire protocol is localhost-only and carries no TLS. Refuse a
    # routable/wildcard bind instead of relying on a warning that can be missed.
    if not _is_loopback_host(host):
        print(
            f"error: refusing non-loopback extension API host {host!r}; the protocol is localhost-only and has no TLS.",
            file=sys.stderr,
        )
        return 2

    try:
        _load_vault_managed_environment()
    except Exception:
        # Secret-provisioning errors can contain vault paths or native backend
        # details.  Stop before accepting RPCs and keep the CLI diagnostic
        # content-free; ``encryption status`` supplies the actionable state.
        print(
            "error: could not load the vault-managed environment; refusing to "
            "start. Run `hermes-mordred encryption status` and repair the env "
            "vault before retrying.",
            file=sys.stderr,
        )
        return 1

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
    color = _term.should_color(sys.stdout)
    return _run_forever(server, host, port, color)


def _run_forever(server: ExtensionAPIServer, host: str, port: int, color: bool) -> int:
    """Own the event loop for the life of the server: bind, print the startup
    banner, block until interrupted, then shut down cleanly.

    Returns ``1`` if binding failed (EADDRINUSE or another OSError), else
    ``0`` after a clean shutdown on Ctrl+C or SIGTERM — the exit code
    :func:`serve` passes straight through to its caller."""
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
                    f"error: port {port} is already in use — something is already "
                    "listening there. Common causes: an `extension serve` process "
                    "already running from an earlier session, or a full Hermes "
                    "gateway already hosting the extension API (nothing to start "
                    "in that case).\n"
                    f"  Run `lsof -i :{port}` to see what's listening, or pass "
                    "--port to use a different one.",
                    file=sys.stderr,
                )
            else:
                print(f"error: could not bind {host}:{port} — {exc}", file=sys.stderr)
            return 1

        # Additive user-facing signal that the server is up. The INFO log
        # line from ExtensionAPIServer.start() ("Mordred extension API on
        # ws://...") is for log consumers; this print is for a human
        # watching the foreground terminal, so it stays even if logging is
        # configured away. should_color() already accounts for a non-tty
        # stdout (piped/redirected), so this degrades to plain text there.
        print()
        print(_term.heading("Mordred Extension server", enabled=color))
        print()
        print(f"WebSocket:  ws://{host}:{port}/ext")
        print(f"Web page:   {server.page_url}")
        print("            (private launch URL; do not share)")
        print()
        print("Press Ctrl+C to stop.")

        try:
            loop.run_until_complete(stop.wait())
        except KeyboardInterrupt:
            pass
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.remove_signal_handler(signal.SIGTERM)
            loop.run_until_complete(server.stop())
            print("Stopped.")
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
        help=f"Loopback bind host (default: {_DEFAULT_HOST}; non-loopback values are refused)",
    )
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT, help=f"Bind port (default: {_DEFAULT_PORT})")
    args = parser.parse_args(argv)
    return serve(host=args.host, port=args.port)


if __name__ == "__main__":
    raise SystemExit(main())
