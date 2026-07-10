"""``hermes mordred extension pair`` — generate a pairing code and wait.

Generates a ``MORT-XXXXXXXX-XXXXXXXX`` code (10-min TTL), prints it plus a
terminal QR, and waits for the gateway's extension WebSocket server to consume
it via a ``pair_init`` from the browser extension.

A WebSocket server must be running to consume the code (it hosts
``ws://localhost:7788/ext``) — either this plugin's own
``hermes-mordred extension serve`` or a full Hermes gateway; this command and
the server hand the code off through ``~/.hermes/extension/pending.json``
(identical layout in both implementations).

See ``Mordred-Extension/SPEC.ja.md`` §3.1 / §7.3.

Pairing-code generation itself is served by the plugin's own ported module
(``mordred_hermes.extension.pairing``, shipped since the #30 port), with the
Hermes-fork ``gateway.extension_pairing`` kept as a fallback for full-gateway
checkouts whose plugin copy predates the port (:func:`_import_pairing`).
"""

from __future__ import annotations

import argparse
import contextlib
import sys
import time
from typing import Any

from . import _term

_POLL_SECONDS = 1.0


class ExtensionGatewayUnavailable(Exception):
    """No pairing backend is importable in this build."""


def _print_qr(code: str) -> None:
    try:
        import qrcode
    except ImportError:
        # The code is still fully usable typed by hand; the QR is a convenience,
        # so a missing optional dep degrades to a note rather than silence.
        _term.emit_note("QR display skipped — `pip install qrcode` to also render the code as a scannable QR.")
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(code)
    qr.make(fit=True)
    with contextlib.suppress(Exception):
        qr.print_ascii(invert=True)


def _import_pairing() -> Any:
    """Import the pairing backend, preferring the plugin's own ported module.

    1. ``mordred_hermes.extension.pairing`` — ships with this plugin (#30
       port). Same ``pending.json`` contract as the full-gateway code, so
       codes generated here are consumable by either server implementation.
       Note the package ``__init__`` eagerly imports ``.api`` (aiohttp), so
       this import needs the ``extension`` extra installed.
    2. ``gateway.extension_pairing`` — Hermes-fork layout, kept as a fallback
       for full-gateway checkouts whose plugin copy predates the port (the
       repo root is added to sys.path when running from such a checkout).

    Raises :class:`ExtensionGatewayUnavailable` — instead of leaking the raw
    ``ImportError`` — when neither is importable: e.g. the published
    ``0.1.0a1`` wheel (predates the extension package) or a newer build
    without the ``extension`` extra's dependencies.
    """
    ported_exc: ImportError
    try:
        from mordred_hermes.extension import pairing as ported

        return ported
    except ImportError as exc:
        ported_exc = exc

    try:
        from gateway import extension_pairing as pairing
    except ImportError:
        import sys
        from pathlib import Path

        here = Path(__file__).resolve()
        for parent in here.parents:
            if (parent / "gateway" / "extension_pairing.py").exists():
                sys.path.insert(0, str(parent))
                break
        try:
            from gateway import extension_pairing as pairing
        except ImportError:
            raise ExtensionGatewayUnavailable(
                "extension pairing is not available in this build: importing "
                f"`mordred_hermes.extension.pairing` failed ({ported_exc}). "
                'Install the `extension` extra (`pip install "mordred-hermes[extension]"` '
                "or, inside this repo, `uv sync --extra extension`) on a build newer "
                "than 0.1.0a1."
            ) from ported_exc
    return pairing


def extension_pair(*, timeout: float = 600.0) -> int:
    """Generate a code and block until paired, the code expires, or Ctrl+C."""
    try:
        pairing = _import_pairing()
    except ExtensionGatewayUnavailable as exc:
        _term.emit_error(str(exc))
        return 2

    code, expires_at = pairing.generate_code()
    color = _term.should_color(sys.stdout)
    ascii_only = not _term.supports_unicode(sys.stdout)
    ttl_minutes = max(1, round((expires_at - time.time()) / 60))

    print()
    print(_term.heading("Mordred Extension pairing", enabled=color))
    print()
    print(f"Pairing code:  {_term.bold(code, enabled=color)}")
    print(f"Expires in {ttl_minutes} minute{'s' if ttl_minutes != 1 else ''}.")
    print()
    _print_qr(code)
    print("Enter this code in the extension's settings page.")
    print("Waiting for the extension to connect... (Ctrl+C to cancel)")

    deadline = min(expires_at, time.time() + timeout)
    try:
        while time.time() < deadline:
            if pairing.code_consumed(code):
                mark = _term.glyph("ok", ascii_only=ascii_only)
                print(f"{_term.success(mark, enabled=color)} Paired ({time.strftime('%Y-%m-%d %H:%M:%S')}).")
                return 0
            time.sleep(_POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nCancelled — no pairing was completed.", file=sys.stderr)
        return 1

    reason = (
        "the pairing code expired before the extension connected"
        if time.time() >= expires_at
        else f"no pairing within {int(timeout)} seconds"
    )
    _term.emit_warn(
        f"{reason} — run `hermes-mordred extension pair` for a new code "
        "(check a server is running: `hermes-mordred extension serve` or a "
        "full Hermes gateway)."
    )
    return 1


def cli_extension_pair(args: argparse.Namespace) -> int:
    return extension_pair(timeout=float(getattr(args, "timeout", 600.0)))
