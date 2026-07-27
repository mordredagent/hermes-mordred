"""Regression: a reply posted INTO A THREAD of an encrypted channel must encrypt.

Real-world trace: the user @-mentions Hermes at channel top level (source has no
thread_id, so the conversation is marked under thread_root=None), and Hermes
answers *in a thread* (thread_ts = the mention's ts). is_encrypted_thread() only
fell back to the channel-level entry when thread_root was None, so the threaded
reply was judged "not encrypted" and went out in CLEARTEXT — even though
thread_key_id() would have resolved the key just fine.
"""
from __future__ import annotations

import asyncio, os, secrets, sys


class FakeClient:
    def __init__(self): self.posts = []
    async def chat_postMessage(self, **kw):
        self.posts.append(kw); return {"ts": "1"}


class FakeSlackAdapter:
    MAX_MESSAGE_LENGTH = 3000
    def __init__(self):
        self._app = object(); self._client = FakeClient(); self._bot_message_ts = set()
    def _get_client(self, c): return self._client
    def _resolve_thread_ts(self, r, m): return (m or {}).get("thread_ts")
    async def stop_typing(self, c): return None
    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self._client.posts.append({"text": content, "PLAINTEXT": True})
        from types import SimpleNamespace
        return SimpleNamespace(success=True)


async def main() -> int:
    assert os.environ.get("HERMES_HOME")
    from mordred_hermes.extension import crypto, pairing, e2e, outbound

    pairing._save_pairing(pairing.Pairing(aes_key=secrets.token_bytes(32), ext_token="t",
        ext_pubkey_b64="", hermes_pubkey_b64="", paired_at=0.0))
    ck = secrets.token_bytes(32)
    pairing.save_channel_key("slack:C0BG9QTCNKE", ck)
    kid = crypto.key_id(ck)

    chat = "C0BG9QTCNKE"
    # Inbound arrived at channel top level -> marked with thread_root=None.
    e2e.mark_encrypted_thread("slack", chat, None, kid)

    # Hermes answers IN A THREAD rooted at the mention.
    thread_ts = "1721550000.001900"
    print("is_encrypted_thread(thread) :", e2e.is_encrypted_thread("slack", chat, thread_ts))
    print("thread_key_id(thread)       :", e2e.thread_key_id("slack", chat, thread_ts))

    outbound._wrap_slack(FakeSlackAdapter)
    a = FakeSlackAdapter()
    await a.send(chat, "Hey! How can I help you today?", metadata={"thread_ts": thread_ts})

    posts = a._client.posts
    leaked = any(p.get("PLAINTEXT") for p in posts)
    enc = [p["text"] for p in posts if not p.get("PLAINTEXT")]
    ok = (not leaked) and enc and all("ENC:v2:" in t for t in enc)
    print("posts:", posts)
    print("\n" + ("PASS — threaded reply encrypted" if ok else "FAIL — CLEARTEXT reply in an encrypted channel"))
    return 0 if ok else 1


sys.exit(asyncio.run(main()))
