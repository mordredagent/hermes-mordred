"""``hermes mordred extension pair`` — generate a pairing code and wait.

Generates a ``MORT-XXXXXXXX-XXXXXXXX`` code (10-min TTL), prints it plus a
terminal QR, and waits for the gateway's extension WebSocket server to consume
it via a ``pair_init`` from the browser extension.

The gateway must be running (it hosts ``ws://localhost:7788/ext``); this command
and the gateway hand the code off through ``~/.hermes/extension/pending.json``.

See ``Mordred-Extension/SPEC.ja.md`` §3.1 / §7.3.
"""

from __future__ import annotations

import argparse
import contextlib
import time
from typing import Any

_POLL_SECONDS = 1.0


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
    the gateway package (a repo-root top-level package) isn't already importable."""
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
        from gateway import extension_pairing as pairing
    return pairing


def extension_pair(*, timeout: float = 600.0) -> int:
    """Generate a code and block until paired, the code expires, or Ctrl+C."""
    pairing = _import_pairing()

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
