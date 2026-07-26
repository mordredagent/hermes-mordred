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
_HEARTBEAT_SECONDS = 30.0
# A consumed code with no recorded outcome is either mid-handshake or was
# claimed by a server build that predates outcome recording (the Hermes-fork
# gateway never writes one). Give the result this long to appear before
# falling back to the legacy claimed-means-paired interpretation. Sized to
# comfortably exceed a slow handshake (SE probe + fsync'd writes behind the
# shared state lock), since the CLI cannot tell WHICH server implementation
# consumed the code; the fallback success also carries an advisory note.
_RESULT_GRACE_SECONDS = 10.0


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
        from pathlib import Path

        here = Path(__file__).resolve()
        for parent in here.parents:
            if (parent / "gateway" / "extension_pairing.py").exists():
                sys.path.insert(0, str(parent))
                break
        try:
            from gateway import extension_pairing as pairing
        except ImportError as gw_exc:
            # Surface BOTH failures: chaining alone would suppress whichever
            # one isn't the explicit cause, and they can differ (missing
            # aiohttp vs. a broken fallback checkout).
            raise ExtensionGatewayUnavailable(
                "extension pairing is not available in this build: importing "
                f"`mordred_hermes.extension.pairing` failed ({ported_exc}); the "
                f"`gateway.extension_pairing` fallback also failed ({gw_exc}). "
                'Install the `extension` extra (`pip install "mordred-hermes[extension]"` '
                "or, inside this repo, `uv sync --extra extension`) on a build newer "
                "than 0.1.0a1."
            ) from ported_exc
    return pairing


def _poll_state(pairing: Any, code: str) -> tuple[str, str | None]:
    """``(state, fail_reason)`` for the pending code — see ``pairing.pair_outcome``.

    Falls back to the legacy ``code_consumed`` probe (claimed vs not) for
    backends that predate outcome recording."""
    outcome = getattr(pairing, "pair_outcome", None)
    if outcome is not None:
        state, fail_reason = outcome(code)
        return str(state), None if fail_reason is None else str(fail_reason)
    return ("consumed" if pairing.code_consumed(code) else "pending", None)


def _sanitize_reason(reason: str | None) -> str:
    """Escape a fail_reason read back from pending.json for terminal display.

    Normally a fixed enum (invalid_challenge / invalid_pubkey /
    internal_error), but the file is same-user-writable state — mirror
    ``_vault_open._display_name``'s control-character escaping so a forged
    value can't inject into the operator's terminal."""
    text = (reason or "unknown")[:80]
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _print_paired(*, color: bool, ascii_only: bool, assumed: bool = False) -> int:
    mark = _term.glyph("ok", ascii_only=ascii_only)
    print(f"{_term.success(mark, enabled=color)} Paired ({time.strftime('%Y-%m-%d %H:%M:%S')}).")
    print(
        "Next: chat from the extension, or open the local page served by "
        "`hermes-mordred extension serve` using the private `Web page:` URL "
        "printed at startup."
    )
    if assumed:
        _term.emit_note(
            "the server never recorded a pairing outcome (an older gateway build?) — "
            "if the extension can't chat, run `hermes-mordred extension pair` again."
        )
    return 0


def _await_outcome(pairing: Any, code: str, deadline: float, *, color: bool, ascii_only: bool) -> int | None:
    """Poll until the code is paired or rejected. Returns the exit code, or
    ``None`` when ``deadline`` passes unclaimed (the caller words the warning:
    expiry vs. timeout).

    ``deadline`` stays wall-clock (it is tied to ``expires_at``, cross-process
    data in pending.json); the heartbeat and grace timers are local elapsed
    time, so they use the monotonic clock and survive NTP steps/sleep-wake."""
    next_heartbeat = time.monotonic() + _HEARTBEAT_SECONDS
    result_grace: float | None = None  # monotonic deadline once "consumed" is seen
    while True:
        state, fail_reason = _poll_state(pairing, code)
        if state == "paired":
            return _print_paired(color=color, ascii_only=ascii_only)
        if state == "failed":
            _term.emit_error(
                f"pairing was rejected ({_sanitize_reason(fail_reason)}). Codes are "
                "single-use: run `hermes-mordred extension pair` for a fresh code "
                "and retry from the extension."
            )
            return 1
        if state == "consumed":
            # Claimed, no outcome yet: wait for the handshake to record a
            # result before assuming a legacy-server success.
            if result_grace is None:
                result_grace = time.monotonic() + _RESULT_GRACE_SECONDS
            elif time.monotonic() >= result_grace:
                return _print_paired(color=color, ascii_only=ascii_only, assumed=True)
        elif time.time() >= deadline:
            return None
        if time.monotonic() >= next_heartbeat:
            remaining = max(0, int(deadline - time.time()))
            print(f"Still waiting… ({remaining // 60}m {remaining % 60:02d}s left, Ctrl+C to cancel)")
            next_heartbeat = time.monotonic() + _HEARTBEAT_SECONDS
        time.sleep(_POLL_SECONDS)


def extension_pair(*, timeout: float = 600.0) -> int:
    """Generate a code and block until paired, rejected, expired, or Ctrl+C."""
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
        rc = _await_outcome(pairing, code, deadline, color=color, ascii_only=ascii_only)
    except KeyboardInterrupt:
        print("\nCancelled — no pairing was completed.", file=sys.stderr)
        return 1
    if rc is not None:
        return rc

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
