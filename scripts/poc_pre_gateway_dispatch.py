"""PoC proof: the Mordred E2E inbound path works as a stock hermes-agent plugin.

Demonstrates that `mordred_hermes.extension.gateway_plugin.pre_gateway_dispatch`
— the single hook that replaces the fork's per-adapter edits — decrypts an
inbound 🔒ENC:v2 ciphertext and drops a 🔑 key-exchange token, using ONLY the
plugin's own crypto + local channel keyring. No gateway/adapter edits involved.

Run:  HERMES_HOME=$(mktemp -d) PYTHONPATH=src python scripts/poc_pre_gateway_dispatch.py
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass
class FakeSource:
    platform: str = "slack"
    chat_id: str = "C0BG9QTCNKE"
    thread_id: Optional[str] = None


@dataclass
class FakeEvent:
    """Minimal stand-in for gateway.platforms.base.MessageEvent (has `.text`)."""

    text: str
    source: FakeSource = None  # type: ignore[assignment]


def main() -> int:
    # Isolated HERMES_HOME so we never touch the real keyring.
    home = os.environ.get("HERMES_HOME")
    assert home, "set HERMES_HOME to a temp dir"

    from mordred_hermes.extension import crypto, pairing
    from mordred_hermes.extension import gateway_plugin as gp

    print("loaded plugin from:", gp.__file__)

    # 1. Seed a keyring: a pairing (master aes_key) + one channel key.
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=secrets.token_bytes(32),
            ext_token="tok",
            ext_pubkey_b64="",
            hermes_pubkey_b64="",
            paired_at=0.0,
        )
    )
    chan_id = "slack:T0B9PPN818F:C0BG9QTCNKE"
    chan_key = secrets.token_bytes(32)
    pairing.save_channel_key(chan_id, chan_key)
    kid = crypto.key_id(chan_key)

    # 2. Encrypt a secret with the channel key → the 🔒ENC:v2 wire token.
    plaintext = "deploy the prod build tonight"
    token = crypto.encrypt_message_v2(chan_key, plaintext, kid)
    inbound = f"<@U0BA8SC0JJ0> {token}"  # leading mention stays plaintext

    # 3. Run the hook exactly as the gateway would.
    res = gp.pre_gateway_dispatch(event=FakeEvent(text=inbound, source=FakeSource()))

    ok = (
        isinstance(res, dict)
        and res.get("action") == "rewrite"
        and plaintext in res.get("text", "")
        and token not in res.get("text", "")  # ciphertext actually replaced
    )
    print("\n[inbound decrypt]")
    print("  wire in :", inbound)
    print("  hook out:", res)
    print("  PASS" if ok else "  FAIL")

    # 4. Key-exchange control message → dropped before the agent.
    kx = gp.pre_gateway_dispatch(event=FakeEvent(text="🔑REQ:v2:abc.def", source=FakeSource()))
    kx_ok = isinstance(kx, dict) and kx.get("action") == "skip"
    print("\n[key-exchange drop]")
    print("  hook out:", kx)
    print("  PASS" if kx_ok else "  FAIL")

    # 5. Plaintext message → untouched (hook returns None).
    passthru = gp.pre_gateway_dispatch(event=FakeEvent(text="hello there", source=FakeSource()))
    pt_ok = passthru is None
    print("\n[plaintext passthrough]")
    print("  hook out:", passthru)
    print("  PASS" if pt_ok else "  FAIL")

    all_ok = ok and kx_ok and pt_ok
    print("\n==== PoC", "PASS ====" if all_ok else "FAIL ====")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
