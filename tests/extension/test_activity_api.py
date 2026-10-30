"""Activity frames over a real ExtensionAPIServer socket (activity_batch_v1).

The receiver is a fake: these tests pin authentication, principal scoping and
size limits, independent of the activity store. Only the paired extension
submits batches (principal ``extension``).
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

from mordred_hermes.activity.contracts import PeerPrincipal
from mordred_hermes.extension import activity_api, extension_api
from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


class FakeReceiver:
    def __init__(self, reply: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[PeerPrincipal, dict[str, Any]]] = []
        self.reply = reply or {
            "type": "activity_ack",
            "status": "ok",
            "accepted": 1,
            "duplicates": 0,
            "episode_revisions": {"ep-1": 1},
        }

    def ingest(self, principal: PeerPrincipal, batch: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((principal, batch))
        return dict(self.reply)


_BATCH = {"schema_version": 1, "producer_id": "p-1", "producer_kind": "browser", "events": [{"event_id": "e1"}]}
_EXTENSION_ORIGIN = {"Origin": "chrome-extension://abc"}


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


async def _extension_pair_and_auth(ws: aiohttp.ClientWebSocketResponse) -> dict[str, Any]:
    """Pair the browser extension, authenticate the socket with its ext_token and return ``auth_ok``."""
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
    assert complete["type"] == "pair_complete", complete
    await ws.send_str(json.dumps({"type": "auth", "ext_token": complete["ext_token"]}))
    auth_ok = await _recv(ws)
    assert auth_ok["type"] == "auth_ok", auth_ok
    return auth_ok


async def _send_batch(ws: aiohttp.ClientWebSocketResponse, batch: Any = _BATCH, mid: str = "b1") -> dict[str, Any]:
    await ws.send_str(json.dumps({"id": mid, "type": "activity_batch", "batch": batch}))
    return await _recv(ws)


def test_extension_batch_ack_reaches_receiver_with_extension_principal():
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as ws:
            auth_ok = await _extension_pair_and_auth(ws)
            reply = await _send_batch(ws)
            await ws.send_str(json.dumps({"id": "s1", "type": "activity_status"}))
            status = await _recv(ws)
            return auth_ok, reply, status

    auth_ok, reply, status = _run(scenario, receiver)
    assert "activity_batch_v1" in auth_ok["capabilities"]
    assert reply == {
        "id": "b1",
        "type": "activity_ack",
        "status": "ok",
        "accepted": 1,
        "duplicates": 0,
        "episode_revisions": {"ep-1": 1},
    }
    [(principal, batch)] = receiver.calls
    assert principal == activity_api.EXTENSION_PRINCIPAL
    assert (principal.peer_id, principal.kind) == ("extension", "browser")
    assert batch == _BATCH
    # Defaults: the activity feature is off for a fresh profile.
    assert status == {"id": "s1", "type": "activity_status", "collection": "disabled", "reason": "collection_disabled"}


def test_receiver_refusal_is_passed_through():
    receiver = FakeReceiver({"type": "activity_refused", "reason": "collection_disabled"})

    async def scenario(session, url, _server):
        async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as ws:
            await _extension_pair_and_auth(ws)
            return await _send_batch(ws)

    assert _run(scenario, receiver) == {"id": "b1", "type": "activity_refused", "reason": "collection_disabled"}
    assert len(receiver.calls) == 1


def test_extension_repairing_revokes_activity_submission_mid_session():
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as ws:
            await _extension_pair_and_auth(ws)
            first = await _send_batch(ws)
            # A new pairing replaces the extension token the first socket authenticated with.
            async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as other:
                await _extension_pair_and_auth(other)
            changed = await _send_batch(ws, mid="b2")
            after = await _send_batch(ws, mid="b3")
            return first, changed, after

    first, changed, after = _run(scenario, receiver)
    assert first["type"] == "activity_ack"
    assert changed == {"type": "auth_fail", "reason": "pairing_changed"}
    assert after == {"type": "auth_fail", "reason": "not_authenticated"}
    assert len(receiver.calls) == 1


@pytest.mark.parametrize(
    "frame",
    [
        {"id": "p", "type": "activity_pair_init", "code": "MORT-AAAAAAAA-AAAAAAAA", "label": "operator"},
        {"type": "activity_auth", "peer_token": "anything"},
    ],
)
def test_operator_peer_frames_are_gone(frame):
    """The operator collector's pairing and auth frames no longer exist: they authenticate nothing."""
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url) as ws:
            await _recv(ws)
            await ws.send_str(json.dumps(frame))
            refused = await _recv(ws)
            return refused, await _send_batch(ws)

    refused, batch = _run(scenario, receiver)
    assert refused == {"type": "auth_fail", "reason": "not_authenticated"}
    assert batch == {"type": "auth_fail", "reason": "not_authenticated"}
    assert receiver.calls == []


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
        async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as ws:
            await _extension_pair_and_auth(ws)
            big = {**_BATCH, "events": [{"event_id": "e", "text": "x" * 3000}]}
            return await _send_batch(ws, big)

    reply = _run(scenario, receiver, activity_max_batch_bytes=2048)
    assert reply == {"id": "b1", "type": "activity_refused", "reason": "batch_too_large"}
    assert receiver.calls == []


def test_default_limit_is_256_kib():
    receiver = FakeReceiver()

    async def scenario(session, url, _server):
        async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as ws:
            await _extension_pair_and_auth(ws)
            big = {**_BATCH, "events": [{"event_id": "e", "text": "x" * (256 * 1024)}]}
            return await _send_batch(ws, big)

    assert _run(scenario, receiver)["reason"] == "batch_too_large"
    assert receiver.calls == []


def test_no_receiver_answers_store_unavailable():
    async def scenario(session, url, _server):
        async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as ws:
            await _extension_pair_and_auth(ws)
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
        async with session.ws_connect(url, headers=_EXTENSION_ORIGIN) as ws:
            await _extension_pair_and_auth(ws)
            malformed = await _send_batch(ws, ["not", "a", "dict"])
            exploded = await _send_batch(ws, mid="b2")
            return malformed, exploded

    malformed, exploded = _run(scenario, Exploding())
    assert malformed == {"id": "b1", "type": "activity_refused", "reason": "malformed"}
    assert exploded == {"id": "b2", "type": "activity_refused", "reason": "store_unavailable"}


@pytest.mark.parametrize("value", [10, 10**9])
def test_configured_limit_is_clamped(tmp_path, monkeypatch, value):
    class Config:
        max_batch_bytes = value

    from mordred_hermes.activity import config

    monkeypatch.setattr(config.ActivityConfig, "load", classmethod(lambda cls, home: Config()))
    limit = activity_api.resolve_max_batch_bytes(tmp_path)
    assert 1024 <= limit <= 4 * 1024 * 1024


@pytest.mark.parametrize(
    ("section", "expected"),
    [
        ({}, ("disabled", "collection_disabled")),
        (
            {"enabled": True, "collection_enabled": True, "excluded_sites": ["bank.example", "not a host"]},
            ("disabled", "excluded_sites_invalid"),
        ),
    ],
)
def test_collection_status_names_the_receivers_refusal(tmp_path, section, expected):
    (tmp_path / "config.yaml").write_text(json.dumps({"plugins": {"mordred_activity": section}}), encoding="utf-8")
    assert activity_api.collection_status(tmp_path) == expected
    assert activity_api.read_activity_switches(tmp_path) == (bool(section), False)
