"""End-to-end WebSocket server test: drives ExtensionAPIServer over a real
socket through the full protocol (pair → auth → crypto → chat → sign), plus the
Origin guard. Uses asyncio.run to avoid a pytest-asyncio dependency."""

from __future__ import annotations

import asyncio
import json
import socket

import aiohttp
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes.extension import extension_api
from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _chat_handler(content, _context):
    for piece in ("こんにちは、", f"受け取りました: {content}"):
        yield piece


async def _run_flow(port: int) -> dict:
    results: dict = {}
    server = extension_api.ExtensionAPIServer(port=port, chat_handler=_chat_handler)
    await server.start()
    try:
        async with aiohttp.ClientSession() as session:
            # Origin guard: a web page origin is rejected.
            try:
                await session.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": "https://evil.example"})
                results["origin_rejected"] = False
            except aiohttp.WSServerHandshakeError as e:
                results["origin_rejected"] = e.status == 403

            async with session.ws_connect(
                f"http://127.0.0.1:{port}/ext", headers={"Origin": "chrome-extension://abc"}
            ) as ws:
                # Server greets with an auth_challenge (§3.5).
                chal = json.loads((await ws.receive()).data)
                results["challenge_type"] = chal["type"]
                results["webauthn_required"] = chal["webauthn_required"]

                # --- pairing ---
                code, _ = pairing.generate_code()
                ext_priv = X25519PrivateKey.generate()
                ext_pub_b64 = xc.b64u_encode(xc.x25519_public_raw(ext_priv))
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "p1",
                            "type": "pair_init",
                            "code": code,
                            "ext_pubkey": ext_pub_b64,
                            "challenge": xc.b64u_encode(b"\x07" * 32),
                        }
                    )
                )
                complete = json.loads((await ws.receive()).data)
                results["pair_type"] = complete["type"]
                ext_key = xc.derive_shared_key(ext_priv, complete["hermes_pubkey"], code)

                # --- auth ---
                await ws.send_str(json.dumps({"type": "auth", "ext_token": complete["ext_token"]}))
                auth = json.loads((await ws.receive()).data)
                results["auth_type"] = auth["type"]

                # --- encrypt then decrypt round-trip via the server ---
                await ws.send_str(json.dumps({"id": "e1", "type": "encrypt", "plaintext": "秘密"}))
                enc = json.loads((await ws.receive()).data)
                results["enc_type"] = enc["type"]
                # The extension would also be able to decrypt locally:
                results["client_decrypt"] = xc.decrypt_message(ext_key, enc["ciphertext"])

                await ws.send_str(json.dumps({"id": "d1", "type": "decrypt", "ciphertext": enc["ciphertext"]}))
                dec = json.loads((await ws.receive()).data)
                results["dec_plaintext"] = dec.get("plaintext")

                # --- chat streaming ---
                await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": "状態"}))
                chat_chunks = []
                while True:
                    m = json.loads((await ws.receive()).data)
                    if m["type"] == "chat_chunk":
                        chat_chunks.append(m["content"])
                    elif m["type"] == "chat_end":
                        break
                results["chat"] = "".join(chat_chunks)

                # --- sign flow (stub the keyvault signer) ---
                import mordred_hermes.extension.api as api_mod

                api_mod._do_sign = lambda method, params, *a: "0xstubbedsig"  # type: ignore[assignment]
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "s1",
                            "type": "sign_request",
                            "request_id": "r1",
                            "method": "personal_sign",
                            "params": ["0xdeadbeef", "0xabc"],
                            "origin": "https://app.uniswap.org",
                        }
                    )
                )
                prompt = json.loads((await ws.receive()).data)
                results["sign_prompt_type"] = prompt["type"]
                results["sign_risk"] = prompt["analysis"]["risk"]
                await ws.send_str(
                    json.dumps({"id": "s2", "type": "sign_approve", "request_id": "r1", "approved": True})
                )
                sresult = json.loads((await ws.receive()).data)
                results["signature"] = sresult.get("signature")
    finally:
        await server.stop()
    return results


def test_full_server_flow():
    r = asyncio.run(_run_flow(_free_port()))
    assert r["origin_rejected"] is True
    assert r["challenge_type"] == "auth_challenge"
    assert r["webauthn_required"] is False
    assert r["pair_type"] == "pair_complete"
    assert r["auth_type"] == "auth_ok"
    assert r["enc_type"] == "encrypt_result"
    assert r["client_decrypt"] == "秘密"
    assert r["dec_plaintext"] == "秘密"
    assert r["chat"] == "こんにちは、受け取りました: 状態"
    assert r["sign_prompt_type"] == "sign_prompt"
    assert r["sign_risk"] == "low"
    assert r["signature"] == "0xstubbedsig"


def test_page_token_auth_and_history():
    """The localhost page authenticates with the per-process page token (only
    from a local origin) and can read/clear the encrypted history."""

    async def _flow(port):
        # Seed some history under the test home.

        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_chat_handler)
        await server.start()
        try:
            # Local origin → page token accepted.
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                json.loads((await ws.receive()).data)  # auth_challenge
                await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
                auth = json.loads((await ws.receive()).data)
                await ws.send_str(json.dumps({"id": "h", "type": "history_get"}))
                hist = json.loads((await ws.receive()).data)
                await ws.send_str(json.dumps({"id": "hc", "type": "history_clear"}))
                cleared = json.loads((await ws.receive()).data)
                return auth["type"], hist["type"], cleared["type"]
        finally:
            await server.stop()

    auth_type, hist_type, cleared_type = asyncio.run(_flow(_free_port()))
    assert auth_type == "auth_ok"
    assert hist_type == "history_result"
    assert cleared_type == "history_cleared"


def test_auth_required_before_commands():
    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s, s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                json.loads((await ws.receive()).data)  # drain auth_challenge
                await ws.send_str(json.dumps({"id": "x", "type": "encrypt", "plaintext": "hi"}))
                return json.loads((await ws.receive()).data)
        finally:
            await server.stop()

    msg = asyncio.run(_flow(_free_port()))
    assert msg["type"] == "auth_fail"
    assert msg["reason"] == "not_authenticated"


def test_keepalive_ping_pushed_to_idle_client():
    """An idle connection must receive app-level pings (MV3 service-worker
    keepalive) without sending anything itself."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port, keepalive_interval=0.05)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s, s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                json.loads((await ws.receive()).data)  # auth_challenge
                return json.loads((await asyncio.wait_for(ws.receive(), timeout=2)).data)
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port())) == {"type": "ping"}


def test_reconnect_reauths_with_persisted_token():
    """A reconnecting client (e.g. after an MV3 service-worker kill) redoes
    only the auth handshake with its stored ext_token — no re-pairing."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                    json.loads((await ws.receive()).data)  # auth_challenge
                    code, _ = pairing.generate_code()
                    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
                    await ws.send_str(
                        json.dumps(
                            {
                                "id": "p1",
                                "type": "pair_init",
                                "code": code,
                                "ext_pubkey": ext_pub,
                                "challenge": xc.b64u_encode(b"\x07" * 32),
                            }
                        )
                    )
                    token = json.loads((await ws.receive()).data)["ext_token"]
                # First socket is closed here — reconnect with the token only.
                async with s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws2:
                    json.loads((await ws2.receive()).data)  # fresh auth_challenge
                    await ws2.send_str(json.dumps({"type": "auth", "ext_token": token}))
                    return json.loads((await ws2.receive()).data)
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port()))["type"] == "auth_ok"


def test_malformed_frames_get_error_and_connection_survives():
    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s, s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                json.loads((await ws.receive()).data)  # auth_challenge
                await ws.send_str("this is {not json")
                bad_json = json.loads((await ws.receive()).data)
                await ws.send_str(json.dumps(["a", "json", "array"]))
                non_dict = json.loads((await ws.receive()).data)
                # The connection must still dispatch normally afterwards.
                await ws.send_str(json.dumps({"type": "auth", "ext_token": "nope"}))
                after = json.loads((await ws.receive()).data)
                return bad_json, non_dict, after
        finally:
            await server.stop()

    bad_json, non_dict, after = asyncio.run(_flow(_free_port()))
    assert bad_json == {"type": "error", "reason": "bad_json"}
    assert non_dict == {"type": "error", "reason": "bad_json"}
    assert after["type"] == "auth_fail"


def test_crashed_handler_replies_error(monkeypatch):
    """A handler exception must produce an id-keyed error frame instead of
    leaving the client to await a reply forever."""
    from mordred_hermes.extension import extension_history

    def _boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(extension_history, "projected_turns", _boom)

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                json.loads((await ws.receive()).data)  # auth_challenge
                await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
                json.loads((await ws.receive()).data)  # auth_ok
                await ws.send_str(json.dumps({"id": "h1", "type": "history_get"}))
                return json.loads((await asyncio.wait_for(ws.receive(), timeout=5)).data)
        finally:
            await server.stop()

    msg = asyncio.run(_flow(_free_port()))
    assert msg == {"id": "h1", "type": "error", "reason": "internal_error"}


def test_ws_chat_client_disconnect_closes_generator():
    """When the client vanishes mid-stream the server must stop consuming the
    chat generator (closing it) instead of streaming into the void."""

    async def _flow(port):
        closed = asyncio.Event()

        async def endless_handler(_content, _context):
            try:
                for i in range(200):
                    yield f"c{i}"
                    await asyncio.sleep(0.05)
            finally:
                closed.set()

        server = extension_api.ExtensionAPIServer(port=port, chat_handler=endless_handler)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.ws_connect(
                    f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}
                ) as ws:
                    json.loads((await ws.receive()).data)  # auth_challenge
                    await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
                    json.loads((await ws.receive()).data)  # auth_ok
                    await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": "x"}))
                    for _ in range(2):  # prove streaming started, then vanish
                        assert json.loads((await ws.receive()).data)["type"] == "chat_chunk"
                await asyncio.wait_for(closed.wait(), timeout=10)
                return True
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port())) is True
