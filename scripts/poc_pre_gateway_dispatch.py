"""PoC proof: the Mordred E2E inbound path works as a stock hermes-agent plugin.

Demonstrates that `mordred_hermes.extension.gateway_plugin.pre_gateway_dispatch`
— the single hook that replaces the fork's per-adapter edits — decrypts an
inbound context-bound 🔒ENC:v3 ciphertext and drops a 🔑 key-exchange token, using ONLY the
plugin's own crypto + local channel keyring. No gateway/adapter edits involved.

Run:  HERMES_HOME=$(mktemp -d) PYTHONPATH=src python scripts/poc_pre_gateway_dispatch.py
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass
from types import SimpleNamespace


@dataclass
class FakeSource:
    platform: str = "slack"
    chat_id: str = "C0BG9QTCNKE"
    thread_id: str | None = None


@dataclass
class FakeEvent:
    """Minimal stand-in for gateway.platforms.base.MessageEvent (has `.text`)."""

    text: str
    source: FakeSource = None  # type: ignore[assignment]


class FakeSlackAdapter:
    """Live-adapter shape needed to prove reply-in-kind is available."""

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        return SimpleNamespace(success=True)


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
    chan_id = FakeSource.chat_id
    chan_key = secrets.token_bytes(32)
    pairing.save_channel_key(chan_id, chan_key)
    kid = crypto.key_id(chan_key)

    # 2. Encrypt a secret with the channel key → the 🔒ENC:v3 wire token.
    plaintext = "deploy the prod build tonight"
    token = crypto.encrypt_message_v3(
        chan_key,
        plaintext,
        kid,
        direction="command",
        platform="slack",
        chat_id=chan_id,
        thread_root=None,
    )
    inbound = f"<@U0BA8SC0JJ0> {token}"  # mention stays plaintext on the wire

    # 3. Run the hook with the gateway's live adapter. Plaintext is released
    # only after the plugin verifies that replies can take the encrypted path.
    gateway = SimpleNamespace(adapters={"slack": FakeSlackAdapter()})
    res = gp.pre_gateway_dispatch(event=FakeEvent(text=inbound, source=FakeSource()), gateway=gateway)

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

    # 5. Plaintext on mandatory-E2E Slack → dropped before the agent.
    passthru = gp.pre_gateway_dispatch(event=FakeEvent(text="hello there", source=FakeSource()))
    pt_ok = isinstance(passthru, dict) and passthru.get("reason") == "mordred-encryption-required"
    print("\n[plaintext refusal]")
    print("  hook out:", passthru)
    print("  PASS" if pt_ok else "  FAIL")

    all_ok = ok and kx_ok and pt_ok
    print("\n==== PoC", "PASS ====" if all_ok else "FAIL ====")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
