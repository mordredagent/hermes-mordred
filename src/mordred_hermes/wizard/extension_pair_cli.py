"""``hermes mordred extension pair`` — generate a pairing code and wait.

Generates a ``MORT-XXXXXXXX-XXXXXXXX`` code (10-min TTL), prints it plus a
terminal QR, and waits for the gateway's extension WebSocket server to consume
it via a ``pair_init`` from the browser extension.

The gateway must be running (it hosts ``ws://localhost:7788/ext``); this command
and the gateway hand the code off through ``~/.hermes/extension/pending.json``.

See ``Mordred-Extension/SPEC.ja.md`` §3.1 / §7.3.

**Standalone-repo status**: ``gateway.extension_pairing`` (and the rest of the
WebSocket server it talks to) lives in the Hermes-fork counterpart to this
plugin, which has not been published alongside this repo yet — see
``docs/dev/ROADMAP.md`` §"Browser-extension gateway counterpart (deferred)".
Until that lands, this command fails closed with a clear message instead of a
raw ``ImportError`` (:func:`_import_pairing`).
"""

from __future__ import annotations

import argparse
import contextlib
import time
from typing import Any

from . import _term

_POLL_SECONDS = 1.0


class ExtensionGatewayUnavailable(Exception):
    """``gateway.extension_pairing`` isn't importable in this build."""


def _print_qr(code: str) -> None:
    try:
        import qrcode
    except ImportError:
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(code)
    qr.make(fit=True)
    with contextlib.suppress(Exception):
        qr.print_ascii(invert=True)


def _import_pairing() -> Any:
    """Import ``gateway.extension_pairing``, adding the repo root to sys.path if
    the gateway package (a repo-root top-level package) isn't already importable.

    Raises :class:`ExtensionGatewayUnavailable` — instead of leaking the raw
    ``ImportError`` — when the Hermes-fork gateway counterpart isn't present,
    which is the expected state for a plain ``pip install mordred-hermes``
    today (see the module docstring's "Standalone-repo status" note).
    """
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
        except ImportError as exc:
            raise ExtensionGatewayUnavailable(
                "the browser-extension gateway (`gateway.extension_pairing`) is not "
                "available in this build. It ships separately from mordred-hermes "
                "and is not published yet — this command is not usable until then."
            ) from exc
    return pairing


def extension_pair(*, timeout: float = 600.0) -> int:
    """Generate a code and block until paired, the code expires, or Ctrl+C."""
    try:
        pairing = _import_pairing()
    except ExtensionGatewayUnavailable as exc:
        _term.emit_error(str(exc))
        return 2

    code, expires_at = pairing.generate_code()

    print("\nMordred Extension ペアリング")
    print("━" * 32)
    print(f"\nペアリングコード:  {code}")
    print("有効期限: 10 分\n")
    _print_qr(code)
    print("\n拡張機能の設定画面でこのコードを入力してください。")
    print(f"コードをコピー: {code}\n")
    print("待機中... (Ctrl+C でキャンセル)")

    deadline = min(expires_at, time.time() + timeout)
    try:
        while time.time() < deadline:
            if pairing.code_consumed(code):
                print(f"✓ ペアリング完了 ({time.strftime('%Y-%m-%d %H:%M:%S')})")
                return 0
            time.sleep(_POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nキャンセルしました。")
        return 1

    print("\n⌛ コードの有効期限が切れました。もう一度実行してください。")
    print("   (ゲートウェイが起動しているか確認してください: `hermes --gateway`)")
    return 1


def cli_extension_pair(args: argparse.Namespace) -> int:
    return extension_pair(timeout=float(getattr(args, "timeout", 600.0)))
