"""Activity frames over a real ExtensionAPIServer socket (activity_batch_v1).

The receiver is a fake: these tests pin authentication, principal scoping,
revalidation and size limits, independent of the activity store.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes.activity import peers
from mordred_hermes.extension import activity_api, extension_api
from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


class FakeReceiver:
    def __init__(self, reply: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[peers.PeerPrincipal, dict[str, Any]]] = []
        self.reply = reply or {
            "type": "activity_ack",
            "status": "ok",
            "accepted": 1,
            "duplicates": 0,
            "episode_revisions": {"ep-1": 1},
        }

    def ingest(self, principal: peers.PeerPrincipal, batch: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((principal, batch))
        return dict(self.reply)


_BATCH = {"schema_version": 1, "producer_id": "p-1", "producer_kind": "operator", "events": [{"event_id": "e1"}]}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _recv(ws: aiohttp.ClientWebSocketResponse) -> dict[str, Any]:
    while True:
        frame = json.loads((await asyncio.wait_for(ws.receive(), timeout=5)).data)
        if frame.get("type") != "ping":
            return frame


Scenario = Callable[[aiohttp.ClientSession, str, Any], Awaitable[Any]]


def _run(scenario: Scenario, receiver: Any = None, **server_kwargs: Any) -> Any:
    async def main() -> Any:
        port = _free_port()
        server = extension_api.ExtensionAPIServer(port=port, activity_receiver=receiver, **server_kwargs)
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                return await scenario(session, f"http://127.0.0.1:{port}/ext", server)
        finally:
            await server.stop()

    return asyncio.run(main())


async def _activity_pair_and_auth(ws: aiohttp.ClientWebSocketResponse) -> dict[str, Any]:
    await _recv(ws)  # auth_challenge
    code, _ = await asyncio.to_thread(peers.generate_peer_code, "test")
    await ws.send_str(json.dumps({"id": "p1", "type": "activity_pair_init", "code": code, "label": "operator"}))
    complete = await _recv(ws)
    assert complete["type"] == "activity_pair_complete", complete
    assert complete["id"] == "p1"
    await ws.send_str(json.dumps({"type": "activity_auth", "peer_token": complete["peer_token"]}))
    ok = await _recv(ws)
    assert ok == {"type": "activity_auth_ok", "peer_id": complete["peer_id"], "capabilities": ["activity_batch_v1"]}
    return complete


async def _send_batch(ws: aiohttp.ClientWebSocketResponse, batch: Any = _BATCH, mid: str = "b1") -> dict[str, Any]:
    await ws.send_str(json.dumps({"id": mid, "type": "activity_batch", "batch": batch}))
    return await _recv(ws)


def test_pair_auth_batch_ack_reaches_receiver_with_peer_principal():
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            complete = await _activity_pair_and_auth(ws)
            reply = await _send_batch(ws)
            await ws.send_str(json.dumps({"id": "s1", "type": "activity_status"}))
            status = await _recv(ws)
            return complete, reply, status

    complete, reply, status = _run(scenario, receiver)
    assert reply == {
        "id": "b1",
        "type": "activity_ack",
        "status": "ok",
        "accepted": 1,
        "duplicates": 0,
        "episode_revisions": {"ep-1": 1},
    }
    [(principal, batch)] = receiver.calls
    assert principal == peers.PeerPrincipal(peer_id=complete["peer_id"], kind="operator")
    assert batch == _BATCH
    # Defaults: the activity feature is off for a fresh profile.
    assert status == {"id": "s1", "type": "activity_status", "collection": "disabled", "reason": "collection_disabled"}


def test_wrong_token_is_refused():
    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _recv(ws)
            await ws.send_str(json.dumps({"type": "activity_auth", "peer_token": "nope"}))
            fail = await _recv(ws)
            reply = await _send_batch(ws)
            return fail, reply

    fail, reply = _run(scenario, FakeReceiver())
    assert fail == {"type": "auth_fail", "reason": "invalid_token"}
    assert reply == {"type": "auth_fail", "reason": "not_authenticated"}


def test_bad_pair_code_fails_without_authenticating():
    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _recv(ws)
            await ws.send_str(json.dumps({"id": "p", "type": "activity_pair_init", "code": "MORT-AAAAAAAA-AAAAAAAA"}))
            return await _recv(ws)

    assert _run(scenario) == {"id": "p", "type": "activity_pair_fail", "reason": "invalid_code"}


def test_revoked_peer_mid_session_gets_pairing_changed():
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            complete = await _activity_pair_and_auth(ws)
            assert (await _send_batch(ws))["type"] == "activity_ack"
            await asyncio.to_thread(peers.revoke, complete["peer_id"])
            changed = await _send_batch(ws, mid="b2")
            after = await _send_batch(ws, mid="b3")
            # Re-auth with the revoked token is refused as such.
            await ws.send_str(json.dumps({"type": "activity_auth", "peer_token": complete["peer_token"]}))
            reauth = await _recv(ws)
            return changed, after, reauth

    changed, after, reauth = _run(scenario, receiver)
    assert changed == {"type": "auth_fail", "reason": "pairing_changed"}
    assert after == {"type": "auth_fail", "reason": "not_authenticated"}
    assert reauth == {"type": "auth_fail", "reason": "peer_revoked"}
    assert len(receiver.calls) == 1


def test_activity_principal_cannot_use_other_handlers():
    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _activity_pair_and_auth(ws)
            replies = []
            for mtype in ("chat", "accounts_request", "history_get", "not_a_frame"):
                await ws.send_str(json.dumps({"id": mtype, "type": mtype, "content": "x"}))
                replies.append(await _recv(ws))
            return replies

    replies = _run(scenario, FakeReceiver())
    assert replies == [
        {"id": mtype, "type": "error", "reason": "activity_session_forbidden"}
        for mtype in ("chat", "accounts_request", "history_get", "not_a_frame")
    ]


def test_page_principal_cannot_submit_activity():
    receiver = FakeReceiver()

    async def scenario(session, url, server):
        async with session.ws_connect(url, headers={"Origin": f"http://127.0.0.1:{server.port}"}) as ws:
            await _recv(ws)
            await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
            assert (await _recv(ws))["type"] == "auth_ok"
            batch = await _send_batch(ws)
            await ws.send_str(json.dumps({"id": "s", "type": "activity_status"}))
            status = await _recv(ws)
            return batch, status

    batch, status = _run(scenario, receiver)
    assert batch == {"id": "b1", "type": "error", "reason": "page_session_forbidden"}
    assert status == {"id": "s", "type": "error", "reason": "page_session_forbidden"}
    assert receiver.calls == []


def test_oversized_raw_frame_is_refused_before_the_receiver():
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _activity_pair_and_auth(ws)
            big = {**_BATCH, "events": [{"event_id": "e", "text": "x" * 3000}]}
            return await _send_batch(ws, big)

    reply = _run(scenario, receiver, activity_max_batch_bytes=2048)
    assert reply == {"id": "b1", "type": "activity_refused", "reason": "batch_too_large"}
    assert receiver.calls == []


def test_default_limit_is_256_kib():
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _activity_pair_and_auth(ws)
            big = {**_BATCH, "events": [{"event_id": "e", "text": "x" * (256 * 1024)}]}
            return await _send_batch(ws, big)

    assert _run(scenario, receiver)["reason"] == "batch_too_large"
    assert receiver.calls == []


def test_no_receiver_answers_store_unavailable():
    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _activity_pair_and_auth(ws)
            reply = await _send_batch(ws)
            await ws.send_str(json.dumps({"id": "s", "type": "activity_status"}))
            return reply, await _recv(ws)

    reply, status = _run(scenario, None)
    assert reply == {"id": "b1", "type": "activity_refused", "reason": "store_unavailable"}
    assert status == {"id": "s", "type": "activity_status", "collection": "unavailable", "reason": "store_unavailable"}


def test_malformed_batch_and_failing_receiver_are_content_free_refusals():
    class Exploding:
        def ingest(self, _principal, _batch):
            raise RuntimeError("secret page text")

    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _activity_pair_and_auth(ws)
            malformed = await _send_batch(ws, ["not", "a", "dict"])
            exploded = await _send_batch(ws, mid="b2")
            return malformed, exploded

    malformed, exploded = _run(scenario, Exploding())
    assert malformed == {"id": "b1", "type": "activity_refused", "reason": "malformed"}
    assert exploded == {"id": "b2", "type": "activity_refused", "reason": "store_unavailable"}


def test_paired_extension_batch_uses_the_extension_principal():
    receiver = FakeReceiver({"type": "activity_refused", "reason": "collection_disabled"})

    async def scenario(session, url, _server):
        async with session.ws_connect(url, headers={"Origin": "chrome-extension://abc"}) as ws:
            challenge = await _recv(ws)
            assert challenge["type"] == "auth_challenge"
            code, _ = await asyncio.to_thread(pairing.generate_code)
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
            auth_ok = await _recv(ws)
            return auth_ok, await _send_batch(ws)

    auth_ok, reply = _run(scenario, receiver)
    assert "activity_batch_v1" in auth_ok["capabilities"]
    assert reply == {"id": "b1", "type": "activity_refused", "reason": "collection_disabled"}
    [(principal, _batch)] = receiver.calls
    assert principal.peer_id == "extension"
    assert principal.kind == "browser"


def test_extension_token_is_not_an_activity_token():
    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _recv(ws)
            code, _ = await asyncio.to_thread(pairing.generate_code)
            await ws.send_str(json.dumps({"id": "p", "type": "activity_pair_init", "code": code}))
            return await _recv(ws)

    assert _run(scenario)["reason"] == "invalid_code"


@pytest.mark.parametrize("value", [10, 10**9])
def test_configured_limit_is_clamped(tmp_path, monkeypatch, value):
    class Config:
        max_batch_bytes = value

    from mordred_hermes.activity import config

    monkeypatch.setattr(config.ActivityConfig, "load", classmethod(lambda cls, home: Config()))
    limit = activity_api.resolve_max_batch_bytes(tmp_path)
    assert 1024 <= limit <= 4 * 1024 * 1024
