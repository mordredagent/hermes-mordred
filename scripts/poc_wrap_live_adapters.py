"""Regression: the wrapper must attach to the adapter the gateway ACTUALLY uses.

Static import paths do not reach the real Slack/Discord adapters — they are
directory-based plugins in a synthetic package that only resolves inside a live
gateway. Wrapping a same-named class from another module silently wraps a class
nobody instantiates and the reply ships in cleartext. Drive it from
GatewayRunner.adapters instead.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sys
from enum import Enum


class Platform(Enum):  # plain Enum like the live gateway's — not a str mixin
    SLACK = "slack"


class RealSlackAdapter:  # stands in for hermes_plugins.slack_platform.adapter
    MAX_MESSAGE_LENGTH = 3000

    def __init__(self):
        self._app = object()
        self.posts = []
        self._bot_message_ts = set()

    def _get_client(self, c):
        return self

    def _resolve_thread_ts(self, r, m):
        return (m or {}).get("thread_ts")

    async def stop_typing(self, c):
        return None

    async def chat_postMessage(self, **kw):
        self.posts.append(kw)
        return {"ts": "1"}

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self.posts.append({"text": content, "PLAINTEXT": True})
        from types import SimpleNamespace

        return SimpleNamespace(success=True)


class FakeGateway:
    def __init__(self, adapter):
        self.adapters = {Platform.SLACK: adapter}


async def main() -> int:
    assert os.environ.get("HERMES_HOME")
    from mordred_hermes.extension import crypto, e2e, outbound, pairing

    pairing._save_pairing(
        pairing.Pairing(
            aes_key=secrets.token_bytes(32), ext_token="t", ext_pubkey_b64="", hermes_pubkey_b64="", paired_at=0.0
        )
    )
    ck = secrets.token_bytes(32)
    pairing.save_channel_key("slack:C0BG9QTCNKE", ck)
    e2e.mark_encrypted_thread("slack", "C0BG9QTCNKE", None, crypto.key_id(ck))

    adapter = RealSlackAdapter()
    gw = FakeGateway(adapter)

    print("wrapped before:", getattr(RealSlackAdapter.send, "__mordred_wrapped__", False))
    outbound.wrap_live_adapters(gw)
    print("wrapped after :", getattr(RealSlackAdapter.send, "__mordred_wrapped__", False))

    await adapter.send("C0BG9QTCNKE", "the answer", metadata={"thread_ts": "1784629318.603409"})
    leaked = any(p.get("PLAINTEXT") for p in adapter.posts)
    enc = [p["text"] for p in adapter.posts if not p.get("PLAINTEXT")]
    ok = (not leaked) and enc and all("ENC:v3:" in t for t in enc)
    print("posts:", adapter.posts)
    print("\n" + ("PASS — live adapter wrapped, reply encrypted" if ok else "FAIL — cleartext"))
    return 0 if ok else 1


sys.exit(asyncio.run(main()))
