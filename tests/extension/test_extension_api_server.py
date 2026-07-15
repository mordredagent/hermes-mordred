"""End-to-end WebSocket server test: drives ExtensionAPIServer over a real
socket through the full protocol (pair → auth → crypto → chat → sign), plus the
Origin guard. Uses asyncio.run to avoid a pytest-asyncio dependency."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat

import aiohttp
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
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


async def _recv(ws):
    """Receive one frame, never block the suite forever on a missing reply."""
    return json.loads((await asyncio.wait_for(ws.receive(), timeout=5)).data)


async def _pair_and_auth(ws) -> bytes:
    """Drive pair_init + auth as the extension would; returns the shared AES key."""
    await _recv(ws)  # auth_challenge
    code, _ = pairing.generate_code()
    ext_priv = X25519PrivateKey.generate()
    await ws.send_str(
        json.dumps(
            {
                "id": "p1",
                "type": "pair_init",
                "code": code,
                "ext_pubkey": xc.b64u_encode(xc.x25519_public_raw(ext_priv)),
                "challenge": xc.b64u_encode(b"\x07" * 32),
            }
        )
    )
    complete = await _recv(ws)
    await ws.send_str(json.dumps({"type": "auth", "ext_token": complete["ext_token"]}))
    await _recv(ws)  # auth_ok
    return xc.derive_shared_key(ext_priv, complete["hermes_pubkey"], code)


async def _page_auth(ws, server) -> None:
    """Authenticate as the keyless localhost page (per-process page token)."""
    await _recv(ws)  # auth_challenge
    await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
    await _recv(ws)  # auth_ok


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


def test_page_session_cannot_touch_credentials(tmp_path):
    """The page token is served in cleartext by ``_handle_page`` to any local
    client and a page session is exempt from WebAuthn (``_on_auth``) — so a page
    session must not reach the credential/key-writing handlers. Above all it must
    not be able to clear the extension's registered second factor."""
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential("cred-1", xc.b64u_encode(spki))

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)
                out = {}
                # Empty fields = "unregister" — the attacker's cheapest move.
                await ws.send_str(json.dumps({"id": "w1", "type": "webauthn_register"}))
                out["webauthn"] = await _recv(ws)
                await ws.send_str(
                    json.dumps({"id": "s1", "type": "slack_setup", "bot_token": "xoxb-a", "app_token": "xapp-b"})
                )
                out["slack"] = await _recv(ws)
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "k1",
                            "type": "channel_key_set",
                            "channel_id": "C1",
                            "key_ct": xc.b64u_encode(b"\x01" * 32),
                        }
                    )
                )
                out["channel"] = await _recv(ws)
                return out
        finally:
            await server.stop()

    out = asyncio.run(_flow(_free_port()))
    assert out["webauthn"] == {
        "id": "w1",
        "type": "webauthn_registered",
        "ok": False,
        "error": "page_session_forbidden",
    }
    assert out["slack"]["error"] == "page_session_forbidden"
    assert out["channel"]["error"] == "page_session_forbidden"
    assert pairing.has_webauthn_credential() is True  # second factor survived
    assert not (tmp_path / ".env").exists()  # no Slack tokens written
    assert pairing.load_channel_keys() == {}


def test_page_session_allowlist_blocks_crypto_and_wallet_but_allows_chat_and_accounts(monkeypatch):
    """Flip side of ``test_page_session_cannot_touch_credentials``: the
    allowlist (``_PAGE_ALLOWED``) must ALSO refuse the K_master crypto oracle
    (``encrypt``/``decrypt``) and the keyvault wallet signer
    (``sign_request``/``sign_approve``) for a page session -- above all a
    denylist would have silently exposed exactly the fund-moving operations
    the WebAuthn hardening exists to protect. And it must still PERMIT the
    two handlers the bundled localhost web app actually uses (``chat``,
    ``accounts_request``), proving the allowlist blocks and permits
    correctly rather than over-blocking."""
    monkeypatch.setattr(extension_api, "_get_address", lambda: "0xabc")

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_chat_handler)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)
                out = {}

                await ws.send_str(json.dumps({"id": "e1", "type": "encrypt", "plaintext": "x"}))
                out["encrypt"] = await _recv(ws)

                await ws.send_str(json.dumps({"id": "d1", "type": "decrypt", "ciphertext": "irrelevant"}))
                out["decrypt"] = await _recv(ws)

                await ws.send_str(
                    json.dumps(
                        {
                            "id": "sr1",
                            "type": "sign_request",
                            "request_id": "r1",
                            "method": "personal_sign",
                            "params": ["0x1"],
                        }
                    )
                )
                out["sign_request"] = await _recv(ws)

                await ws.send_str(
                    json.dumps({"id": "sa1", "type": "sign_approve", "request_id": "r1", "approved": True})
                )
                out["sign_approve"] = await _recv(ws)

                # Positive: allowlisted handlers still work for a page session.
                await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": "hi"}))
                chunks = []
                while True:
                    m = await _recv(ws)
                    if m["type"] == "chat_chunk":
                        chunks.append(m["content"])
                    elif m["type"] == "chat_end":
                        break
                out["chat"] = "".join(chunks)

                await ws.send_str(json.dumps({"id": "a1", "type": "accounts_request"}))
                out["accounts"] = await _recv(ws)

                return out
        finally:
            await server.stop()

    out = asyncio.run(_flow(_free_port()))
    assert out["encrypt"] == {"id": "e1", "type": "encrypt_fail", "ok": False, "error": "page_session_forbidden"}
    assert out["decrypt"] == {"id": "d1", "type": "decrypt_fail", "ok": False, "error": "page_session_forbidden"}
    assert out["sign_request"] == {"id": "sr1", "type": "sign_result", "ok": False, "error": "page_session_forbidden"}
    assert out["sign_approve"] == {"id": "sa1", "type": "sign_result", "ok": False, "error": "page_session_forbidden"}
    # Never reached the wallet signer -- no pending sign entry was even created.
    assert out["chat"] == "こんにちは、受け取りました: hi"
    assert out["accounts"]["type"] == "accounts_result"
    assert out["accounts"]["accounts"] == ["0xabc"]


def test_slack_setup_rejects_newline_bearing_token(tmp_path):
    """``.strip()`` + ``startswith`` let an *internal* newline through, and the
    token is written as a raw ``KEY=value`` line — so "xoxb-x\\nEVIL=..." would
    inject an extra dotenv entry that Hermes loads on its next restart."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": "chrome-extension://abc"}) as ws,
            ):
                await _pair_and_auth(ws)
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "s1",
                            "type": "slack_setup",
                            "bot_token": "xoxb-x\nEVIL=pwned",
                            "app_token": "xapp-1-A",
                        }
                    )
                )
                bad = await _recv(ws)
                # A well-formed pair must still be accepted (no over-blocking).
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "s2",
                            "type": "slack_setup",
                            "bot_token": "xoxb-123456-abcDEF",
                            "app_token": "xapp-1-A01-9zz",
                        }
                    )
                )
                good = await _recv(ws)
                return bad, good
        finally:
            await server.stop()

    bad, good = asyncio.run(_flow(_free_port()))
    assert bad["ok"] is False
    assert bad["error"] == "bad_token_format"
    assert good["ok"] is True
    env = (tmp_path / ".env").read_text()
    assert "EVIL=pwned" not in env  # nothing injected
    assert "SLACK_BOT_TOKEN=xoxb-123456-abcDEF" in env


def test_upsert_env_vars_rejects_newlines(tmp_path):
    """Last line of defence: the writer itself refuses CR/LF in a key or value."""
    env = tmp_path / ".env"
    with pytest.raises(ValueError):
        extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-x\nEVIL=pwned"})
    with pytest.raises(ValueError):
        extension_api._upsert_env_vars(env, {"SLACK\rBOT": "x"})
    assert not env.exists()


def test_upsert_env_vars_new_file_is_0600(tmp_path):
    """This file holds Slack bot/app tokens, so a plain ``write_text`` would
    leave a freshly-created ``.env`` at the umask default (typically 0o644,
    world-readable) rather than the atomic writer's tmp-file mode."""
    env = tmp_path / ".env"
    extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-a"})
    assert oct(stat.S_IMODE(os.stat(env).st_mode)) == "0o600"


def test_upsert_env_vars_tightens_a_loosely_permissioned_existing_file(tmp_path):
    """A host-managed ``.env`` may legitimately pre-exist at 0o644 (unlike
    ``keyvault._storage.atomic_write``, which refuses that case outright) --
    ``os.replace`` gives the result the tmp file's 0o600 mode, tightening the
    permissions rather than preserving the leak."""
    env = tmp_path / ".env"
    env.write_text("EXISTING=1\n", encoding="utf-8")
    os.chmod(env, 0o644)

    extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-a"})

    assert oct(stat.S_IMODE(os.stat(env).st_mode)) == "0o600"


def test_upsert_env_vars_preserves_unrelated_existing_vars(tmp_path):
    """The atomic upsert (mkstemp + os.replace) must not clobber vars already
    in the file that the update did not touch."""
    env = tmp_path / ".env"
    env.write_text("KEEP_ME=untouched\nSLACK_BOT_TOKEN=old\n", encoding="utf-8")

    extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-new"})

    text = env.read_text(encoding="utf-8")
    assert "KEEP_ME=untouched" in text
    assert "SLACK_BOT_TOKEN=xoxb-new" in text
    assert "SLACK_BOT_TOKEN=old" not in text


def test_encrypt_without_pairing_replies_encrypt_fail():
    """A page session hitting ``encrypt`` is now refused BEFORE ``_on_encrypt``
    even runs: the page allowlist (``_PAGE_ALLOWED``) added later blocks
    ``encrypt`` for page sessions outright, so the reply is the allowlist's
    ``page_session_forbidden`` on type ``encrypt_fail`` -- not the handler's own
    ``not_paired`` reason. See ``test_on_encrypt_not_paired_replies_encrypt_fail``
    below for direct coverage of the ``_on_encrypt`` reply-type-rename fix
    (``encrypt_fail`` used to be a copy-pasted ``decrypt_fail``), exercised at
    the unit level since a page session can no longer reach that branch."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)  # authed but keyless: no pairing exists
                await ws.send_str(json.dumps({"id": "e1", "type": "encrypt", "plaintext": "x"}))
                return await _recv(ws)
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port())) == {
        "id": "e1",
        "type": "encrypt_fail",
        "ok": False,
        "error": "page_session_forbidden",
    }


def test_chat_undecryptable_ciphertext_is_not_forwarded_to_the_agent():
    """A stale K_extchat (e.g. the client re-paired) must yield a ``chat_error``
    — forwarding the still-encrypted blob would hand the agent ciphertext as the
    user's message."""
    seen: list[str] = []

    async def _recording_handler(content, _context):
        seen.append(content)
        yield "ok"

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_recording_handler)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": "chrome-extension://abc"}) as ws,
            ):
                aes = await _pair_and_auth(ws)
                stale = xc.encrypt_message(b"\x09" * 32, "hello")  # not our K_extchat
                await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": stale}))
                err = await _recv(ws)
                # A correctly-keyed encrypted message must still get through.
                ek = xc.hkdf_subkey(aes, extension_api._EXTCHAT_SALT, extension_api._EXTCHAT_INFO)
                await ws.send_str(json.dumps({"id": "c2", "type": "chat", "content": xc.encrypt_message(ek, "hi")}))
                ok = await _recv(ws)
                return err, ok
        finally:
            await server.stop()

    err, ok = asyncio.run(_flow(_free_port()))
    assert err == {"id": "c1", "type": "chat_error", "reason": "undecryptable"}
    assert ok["type"] == "chat_chunk"
    assert seen == ["hi"]  # the agent never saw the undecryptable blob


class _FakeWS:
    """Minimal stand-in for ``web.WebSocketResponse`` — ``_Connection`` only ever
    touches ``closed`` and ``send_str``."""

    def __init__(self):
        self.closed = False
        self.sent: list[dict] = []

    async def send_str(self, data: str) -> None:
        self.sent.append(json.loads(data))


def _authed_conn() -> extension_api._Connection:
    conn = extension_api._Connection(_FakeWS(), _chat_handler)
    conn.authed = True
    return conn


def test_on_encrypt_not_paired_replies_encrypt_fail(monkeypatch):
    """Direct unit coverage for the ``_on_encrypt`` reply-type-rename fix: the
    not-paired branch used to answer with ``decrypt_fail`` (copy-paste from
    ``_on_decrypt``), which no client keys a reply on. A page session can no
    longer reach this branch at all (the allowlist refuses ``encrypt`` for
    page sessions before ``_on_encrypt`` runs — see
    ``test_encrypt_without_pairing_replies_encrypt_fail`` above), so exercise
    ``_on_encrypt`` directly on an authed, non-page connection with no pairing
    on disk."""
    monkeypatch.setattr(pairing, "load_pairing", lambda: None)
    conn = extension_api._Connection(_FakeWS(), _chat_handler, page_token=None)
    conn.authed = True
    asyncio.run(conn._on_encrypt({"id": "e1", "type": "encrypt", "plaintext": "x"}))
    assert conn.ws.sent == [{"id": "e1", "type": "encrypt_fail", "reason": "not_paired"}]


def test_sign_request_without_request_id_is_rejected():
    """An empty request_id collapsed every id-less request onto "" — a second
    one silently overwrote the first's frozen params."""
    conn = _authed_conn()
    asyncio.run(
        conn.dispatch(json.dumps({"id": "s1", "type": "sign_request", "method": "personal_sign", "params": ["0x1"]}))
    )
    assert conn.ws.sent == [{"id": "s1", "type": "sign_result", "request_id": "", "error": "missing_request_id"}]
    assert conn._pending_sign == {}


def test_sign_request_duplicate_request_id_is_rejected():
    """Wallet "approve A, sign B" defense: re-using a ``request_id`` that is
    still pending must be refused outright, not silently overwrite the frozen
    params of the prompt already shown to the user — otherwise a dapp could
    display a benign tx, then swap in a draining tx under the same id before
    the user clicks approve."""
    conn = _authed_conn()
    first_params = ["0xfirst"]
    second_params = ["0xsecond"]

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": "dup",
                    "method": "personal_sign",
                    "params": first_params,
                }
            )
        )
    )
    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s2",
                    "type": "sign_request",
                    "request_id": "dup",
                    "method": "personal_sign",
                    "params": second_params,
                }
            )
        )
    )

    assert conn.ws.sent[-1] == {"id": "s2", "type": "sign_result", "request_id": "dup", "error": "duplicate_request_id"}
    # The first request's frozen params must survive untouched.
    assert conn._pending_sign["dup"]["params"] == first_params


def test_pending_sign_table_is_bounded():
    """Entries only leave ``_pending_sign`` on approve/reject, so an authed socket
    that never approves must not grow it without bound."""
    conn = _authed_conn()
    n = extension_api._MAX_PENDING_SIGN + 10

    async def _fire():
        for i in range(n):
            await conn.dispatch(
                json.dumps(
                    {
                        "id": f"s{i}",
                        "type": "sign_request",
                        "request_id": f"r{i}",
                        "method": "personal_sign",
                        "params": ["0x1"],
                    }
                )
            )

    asyncio.run(_fire())
    assert len(conn._pending_sign) == extension_api._MAX_PENDING_SIGN
    assert "r0" not in conn._pending_sign  # oldest evicted
    assert f"r{n - 1}" in conn._pending_sign  # newest kept


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
