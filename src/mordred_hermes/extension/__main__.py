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
from collections.abc import Callable
from types import FrameType
from typing import TYPE_CHECKING, Any

from .. import _term

if TYPE_CHECKING:
    from .api import ExtensionAPIServer

# Mirrors mordred_hermes.extension.api.DEFAULT_HOST / DEFAULT_PORT (protocol
# constants, SPEC.ja.md §6). Hardcoded rather than imported at module scope so
# importing *this* module never pulls in aiohttp — see the module docstring.
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 7788
# Winsock codes (errno on Windows): WSAEADDRINUSE, WSAEACCES.
_WSAEADDRINUSE = 10048
_WSAEACCES = 10013
# How long a stop waits for in-flight connections (an open extension
# WebSocket never finishes on its own) before they are cancelled. The
# listener is closed first, so the port is released at the start of the stop.
_STOP_GRACE_SECONDS = 3.0


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
    shutdown on Ctrl+C, SIGTERM or (Windows) Ctrl+Break. Shutdown closes the
    listener first and gives open connections a short grace period, so a
    connected extension cannot hold the process (or the port) open.
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


def _bind_failure(exc: OSError, host: str, port: int, *, platform: str = sys.platform) -> str:
    """One classified line (plus hints) for a refused bind; another port is never tried silently.

    ``port-in-use``: something already listens there. ``port-forbidden``: the
    port is reserved (a Windows excluded port range) or exclusively held, or
    privileged. ``bind-failed``: anything else (bad host, unavailable address).
    """
    windows = platform == "win32"
    if exc.errno in (errno.EADDRINUSE, _WSAEADDRINUSE):
        holder = (
            f"Run `Get-NetTCPConnection -LocalPort {port} -State Listen` (PowerShell) to see what's listening"
            if windows
            else f"Run `lsof -i :{port}` to see what's listening"
        )
        return (
            f"error: port {port} is already in use (port-in-use) — something is already "
            "listening there. Common causes: an `extension serve` process "
            "already running from an earlier session, or a full Hermes "
            "gateway already hosting the extension API (nothing to start "
            "in that case).\n"
            f"  {holder}, or pass --port to use a different one. No other port is tried."
        )
    if exc.errno in (errno.EACCES, _WSAEACCES):
        reserved = (
            " Windows may reserve it in an excluded port range "
            "(`netsh interface ipv4 show excludedportrange protocol=tcp`) or another process may hold it exclusively."
            if windows
            else ""
        )
        return (
            f"error: port {port} cannot be bound on {host} (port-forbidden).{reserved}\n"
            "  Pass --port to choose another port. No other port is tried."
        )
    return (
        f"error: could not bind {host}:{port} (bind-failed) — {exc}. Pass --port to change it; no other port is tried."
    )


def _threadsafe_stop(loop: asyncio.AbstractEventLoop, stop: asyncio.Event) -> Callable[[int, FrameType | None], None]:
    """A ``signal.signal`` handler that asks the loop to stop from whatever thread/frame it runs in.

    A late console event after the loop closed is ignored rather than raised.
    """

    def handler(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(stop.set)

    return handler


def _stop_signals() -> tuple[int, ...]:
    """Console signals routed through ``signal.signal`` when the loop has no ``add_signal_handler``.

    Windows' proactor loop raises ``NotImplementedError`` there. ``CTRL_BREAK_EVENT``
    arrives as ``SIGBREAK``, whose default action ends the process without
    ``server.stop()``. Ctrl-C keeps the ``KeyboardInterrupt`` path.
    """
    sigbreak = getattr(signal, "SIGBREAK", None)
    return (int(sigbreak),) if sigbreak is not None else ()


def _install_stop_handlers(loop: asyncio.AbstractEventLoop, stop: asyncio.Event) -> Callable[[], None]:
    """Route SIGTERM (POSIX) or SIGBREAK (Windows) to ``stop``; return the undo callable."""
    try:
        loop.add_signal_handler(signal.SIGTERM, stop.set)
    except (NotImplementedError, RuntimeError, ValueError):
        pass
    else:

        def remove() -> None:
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.remove_signal_handler(signal.SIGTERM)

        return remove
    handler = _threadsafe_stop(loop, stop)
    previous: dict[int, Any] = {}
    for signum in _stop_signals():
        with contextlib.suppress(ValueError, OSError):  # e.g. not the main thread
            previous[signum] = signal.signal(signum, handler)

    def restore() -> None:
        for signum, old in previous.items():
            with contextlib.suppress(ValueError, OSError, TypeError):
                signal.signal(signum, old)

    return restore


async def _bounded_stop(server: ExtensionAPIServer, grace: float) -> None:
    """``server.stop()`` (listener first, then connections), cut off after ``grace`` seconds.

    aiohttp waits up to 60 s for every open handler; a connected extension's
    WebSocket handler only ends when the client leaves, so an unbounded stop
    could hang a Ctrl-C/Ctrl-Break/SIGTERM for most of a minute.
    """
    try:
        await asyncio.wait_for(server.stop(), timeout=grace)
    except TimeoutError:
        logging.getLogger(__name__).info("closing connections still open after %.0f s", grace)


def _cancel_remaining(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel the connection handlers a bounded stop left behind, as ``asyncio.run`` would."""
    pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
    for task in pending:
        task.cancel()
    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))


def _run_forever(server: ExtensionAPIServer, host: str, port: int, color: bool) -> int:
    """Own the event loop for the life of the server: bind, print the startup
    banner, block until interrupted, then shut down cleanly.

    Returns ``1`` if binding failed (EADDRINUSE or another OSError), else
    ``0`` after a clean shutdown on Ctrl+C, SIGTERM or (Windows) Ctrl+Break —
    the exit code :func:`serve` passes straight through to its caller."""
    # A manually managed loop (vs. asyncio.run) so the EADDRINUSE / Ctrl+C
    # paths below can each call `server.stop()` deterministically on the same
    # loop before it closes, instead of relying on asyncio.run()'s implicit
    # task-cancellation cleanup.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # systemd / `docker stop` / plain `kill` send SIGTERM; route it through
        # the same clean shutdown as Ctrl+C so supervisors see exit 0 rather
        # than an abrupt signal death. Windows has no add_signal_handler on the
        # proactor loop: Ctrl+Break (SIGBREAK) goes through signal.signal and
        # loop.call_soon_threadsafe instead. Installed BEFORE binding: a
        # supervisor (or the shutdown test) may signal as soon as the port
        # accepts, which happens inside server.start().
        stop = asyncio.Event()
        restore_signals = _install_stop_handlers(loop, stop)
        try:
            loop.run_until_complete(server.start())
        except OSError as exc:
            # gaierror (bad --host) and PermissionError (privileged port) are
            # OSError subclasses — every bind failure gets the same one-line
            # error UX instead of a traceback.
            loop.run_until_complete(server.stop())
            restore_signals()
            print(_bind_failure(exc, host, port), file=sys.stderr)
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
        print("Press Ctrl+C to stop." if sys.platform != "win32" else "Press Ctrl+C (or Ctrl+Break) to stop.")

        try:
            loop.run_until_complete(stop.wait())
        except KeyboardInterrupt:
            pass
        finally:
            restore_signals()
            loop.run_until_complete(_bounded_stop(server, _STOP_GRACE_SECONDS))
            _cancel_remaining(loop)
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
