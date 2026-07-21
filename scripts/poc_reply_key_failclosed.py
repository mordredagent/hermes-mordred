"""Regression: a reply must never be encrypted with the master/pairing key.

The master is not a channel key any extension holds, so such a reply is
unreadable by everyone while still *looking* encrypted. reply_key() must
fail closed (None) when the inbound keyId hint is missing/unknown, and the
send path must surface a visible notice instead of emitting ciphertext.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import sys


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
    assert os.environ.get("HERMES_HOME"), "set HERMES_HOME"
    from mordred_hermes.extension import crypto, pairing, e2e, outbound

    master = secrets.token_bytes(32)
    pairing._save_pairing(pairing.Pairing(aes_key=master, ext_token="t",
        ext_pubkey_b64="", hermes_pubkey_b64="", paired_at=0.0))
    chan = secrets.token_bytes(32)
    pairing.save_channel_key("slack:T:C", chan)

    ok = True

    # 1. Missing hint -> must NOT return the master key.
    k = e2e.reply_key(None)
    print("reply_key(None)          ->", "None" if k is None else "SOME KEY")
    if k is not None:
        ok = False; print("   FAIL: fell back to a key (master) nobody can read")

    # 2. Unknown hint -> must NOT return the master key.
    k = e2e.reply_key("ZZZZunknown")
    print("reply_key('ZZZZunknown') ->", "None" if k is None else "SOME KEY")
    if k is not None:
        ok = False; print("   FAIL: fell back to a key (master)")

    # 3. Known channel keyId -> resolves.
    k = e2e.reply_key(crypto.key_id(chan))
    print("reply_key(<channel kid>) ->", "channel key" if k == chan else "WRONG")
    if k != chan:
        ok = False

    # 4. v1/legacy: remembered kid IS the master's -> must still resolve.
    k = e2e.reply_key(crypto.key_id(master))
    print("reply_key(<master kid>)  ->", "master (v1 legacy ok)" if k == master else "WRONG")
    if k != master:
        ok = False; print("   FAIL: broke v1/legacy conversations")

    # 5. End-to-end: encrypted thread with NO usable kid must post a notice,
    #    never ciphertext and never plaintext.
    e2e.mark_encrypted_thread("slack", "C", "t1", None)   # marked, but kid unknown
    outbound._wrap_slack(FakeSlackAdapter)
    a = FakeSlackAdapter()
    await a.send("C", "sensitive answer", metadata={"thread_ts": "t1"})
    posts = a._client.posts
    leaked_plain = any(p.get("PLAINTEXT") for p in posts)
    unreadable = any("ENC:v2:" in p.get("text", "") for p in posts)
    noticed = any("暗号化できない" in p.get("text", "") for p in posts)
    print("send with unknown kid   ->", posts)
    if leaked_plain: ok = False; print("   FAIL: plaintext leak")
    if unreadable:   ok = False; print("   FAIL: emitted ciphertext nobody can read")
    if not noticed:  ok = False; print("   FAIL: no visible notice")

    print("\n" + ("PASS — reply key is fail-closed" if ok else "FAIL"))
    return 0 if ok else 1


sys.exit(asyncio.run(main()))
