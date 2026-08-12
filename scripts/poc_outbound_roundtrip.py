"""PoC proof (outbound): reply-in-kind encryption via the plugin send-wrapper.

Simulates a Slack adapter in an encrypted thread: the wrapped `send` must emit
🔒ENC ciphertext (never plaintext), and that ciphertext must decrypt back to the
original reply via the same inbound path. No real Slack connection needed — a
fake client captures chat_postMessage calls.

Run:  HERMES_HOME=$(mktemp -d) PYTHONPATH=src python scripts/poc_outbound_roundtrip.py
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sys


class FakeSlackClient:
    def __init__(self):
        self.posts = []

    async def chat_postMessage(self, **kw):
        self.posts.append(kw)
        return {"ts": f"ts{len(self.posts)}"}


class FakeSlackAdapter:
    """Minimal stand-in exposing the attributes the wrapper touches."""

    MAX_MESSAGE_LENGTH = 3000

    def __init__(self):
        self._app = object()
        self._client = FakeSlackClient()
        self._bot_message_ts = set()

    def _get_client(self, chat_id):
        return self._client

    def _resolve_thread_ts(self, reply_to, metadata):
        return (metadata or {}).get("thread_ts")

    async def stop_typing(self, chat_id):
        return None

    # The "original" plaintext send — the wrapper must NOT call this in an
    # encrypted thread. If it does, we detect the leak.
    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self._client.posts.append({"channel": chat_id, "text": content, "PLAINTEXT_LEAK": True})
        from types import SimpleNamespace

        return SimpleNamespace(success=True)


async def main() -> int:
    assert os.environ.get("HERMES_HOME"), "set HERMES_HOME to a temp dir"

    from mordred_hermes.extension import crypto, e2e, outbound, pairing

    # Seed a channel key and mark a Slack thread encrypted (as the inbound hook would).
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=secrets.token_bytes(32),
            ext_token="t",
            ext_pubkey_b64="",
            hermes_pubkey_b64="",
            paired_at=0.0,
        )
    )
    chan_key = secrets.token_bytes(32)
    pairing.save_channel_key("slack:T:C", chan_key)
    kid = crypto.key_id(chan_key)
    chat_id, thread_ts = "C", "1710000000.0001"
    e2e.mark_encrypted_thread("slack", chat_id, thread_ts, kid)

    # Wrap the fake adapter class and send a reply into the encrypted thread.
    outbound._wrap_slack(FakeSlackAdapter)
    adapter = FakeSlackAdapter()
    reply = "roger — deploying now"
    res = await adapter.send(chat_id, reply, metadata={"thread_ts": thread_ts})

    posts = adapter._client.posts
    leaked = any(p.get("PLAINTEXT_LEAK") for p in posts)
    texts = [p["text"] for p in posts if "text" in p and not p.get("PLAINTEXT_LEAK")]
    encrypted = bool(texts) and all(("ENC:v3:" in t) for t in texts)
    mrkdwn_off = all(p.get("mrkdwn") is False for p in posts if "text" in p and not p.get("PLAINTEXT_LEAK"))

    # Round-trip as a browser receiver (reply direction, exact destination).
    back = "".join(
        crypto.decrypt_message_v3(
            chan_key,
            text,
            direction="reply",
            platform="slack",
            chat_id=chat_id,
            thread_root=thread_ts,
        )
        for text in texts
    )

    print("[outbound encrypt]")
    print("  posted        :", texts)
    print("  plaintext leak :", leaked)
    print("  all ENC:v3     :", encrypted, "| mrkdwn=False:", mrkdwn_off)
    print("  decrypts back  :", back)
    print("  send result ok :", getattr(res, "success", None))

    ok = (not leaked) and encrypted and mrkdwn_off and (back is not None) and (reply in back)
    print("\n==== outbound reply-in-kind round-trip:", "PASS ====" if ok else "FAIL ====")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
