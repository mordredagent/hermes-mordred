"""Regression: inbound must mark the thread under the SAME platform string the
outbound wrapper looks up, or replies leak in cleartext."""

from __future__ import annotations

import asyncio
import secrets
import sys
from dataclasses import dataclass
from enum import StrEnum
from types import SimpleNamespace


class Platform(StrEnum):  # mirrors gateway.platforms.base.Platform
    SLACK = "slack"


@dataclass
class Src:
    platform: Platform = Platform.SLACK
    chat_id: str = "C0BG9QTCNKE"
    thread_id: str | None = None


@dataclass
class Ev:
    text: str
    source: Src | None = None


class FakeClient:
    def __init__(self):
        self.posts = []

    async def chat_postMessage(self, **kw):
        self.posts.append(kw)
        return {"ts": "1"}


class FakeSlackAdapter:
    MAX_MESSAGE_LENGTH = 3000

    def __init__(self):
        self._app = object()
        self._client = FakeClient()
        self._bot_message_ts = set()

    def _get_client(self, c):
        return self._client

    def _resolve_thread_ts(self, r, m):
        return (m or {}).get("thread_ts")

    async def stop_typing(self, c):
        return None

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self._client.posts.append({"text": content, "PLAINTEXT": True})
        return SimpleNamespace(success=True)


async def main():
    from mordred_hermes.extension import crypto, pairing
    from mordred_hermes.extension import gateway_plugin as gp

    pairing._save_pairing(
        pairing.Pairing(
            aes_key=secrets.token_bytes(32),
            ext_token="t",
            ext_pubkey_b64="",
            hermes_pubkey_b64="",
            paired_at=0.0,
        )
    )
    ck = secrets.token_bytes(32)
    pairing.save_channel_key(Src.chat_id, ck)
    tok = crypto.encrypt_message_v3(
        ck,
        "secret plan",
        crypto.key_id(ck),
        direction="command",
        platform="slack",
        chat_id=Src.chat_id,
        thread_root=None,
    )

    # 1) inbound: hook verifies the live outbound path, decrypts, AND marks the
    # thread (platform enum!).
    a = FakeSlackAdapter()
    gateway = SimpleNamespace(adapters={Platform.SLACK: a})
    r = gp.pre_gateway_dispatch(event=Ev(text=tok, source=Src()), gateway=gateway)
    assert r and r.get("action") == "rewrite", r

    # 2) outbound: reply into that same conversation MUST be encrypted
    await a.send("C0BG9QTCNKE", "here is my answer", metadata={})

    leaked = any(p.get("PLAINTEXT") for p in a._client.posts)
    enc = [p["text"] for p in a._client.posts if not p.get("PLAINTEXT")]
    ok = (not leaked) and enc and all("ENC:v3:" in t for t in enc)
    print("posts:", a._client.posts)
    print("PASS — reply encrypted" if ok else "FAIL — CLEARTEXT LEAK in encrypted channel")
    return 0 if ok else 1


sys.exit(asyncio.run(main()))
