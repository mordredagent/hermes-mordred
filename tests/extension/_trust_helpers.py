"""Stand-ins for the vault-backed trust store in API tests."""

from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils, x25519

from mordred_hermes.extension import trust

DEVICE_ID = "test-device"
GENERATION = b"g" * 32


class FixedTrustStore:
    """``load()`` answers with fixed devices; ``remove()`` drops one."""

    def __init__(self, devices: dict[str, bytes]) -> None:
        self.devices = dict(devices)

    def load(self, *, fresh: bool = False) -> Any:
        return SimpleNamespace(devices={k: SimpleNamespace(device_id=k, generation=g) for k, g in self.devices.items()})

    def remove(self, device_id: str) -> bool:
        return self.devices.pop(device_id, None) is not None


def authenticate(conn: Any, key: bytes, device_id: str = DEVICE_ID) -> FixedTrustStore:
    """Mark ``conn`` as an endorsed browser's socket whose session key is ``key``."""
    fixed = FixedTrustStore({device_id: GENERATION})
    trust.set_store(fixed)  # type: ignore[arg-type]
    conn.authed = True
    conn._device_id = device_id
    conn._device_generation = GENERATION
    conn._session_key = key
    return fixed


class MemoryVault:
    """The vault surface :class:`trust.TrustStore` uses, in memory."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.generation = 0
        #: How often the store unwrapped the master (each one is a Touch ID prompt).
        self.opens = 0

    def list_files(self) -> list[str]:
        return list(self.files)

    def read_file(self, name: str) -> bytes:
        return self.files[name]

    def enroll_file(self, name: str, plaintext: bytes) -> None:
        self.files[name] = plaintext
        self.generation += 1

    def open(self) -> tuple[MemoryVault, str]:
        self.opens += 1
        return self, "mordred-hermes.vault.test"

    def store(self, **kwargs: Any) -> trust.TrustStore:
        return trust.TrustStore(opener=self.open, probe=lambda: self.generation, **kwargs)

    def close(self) -> None:
        pass


def with_test_root(monkeypatch: Any) -> tuple[trust.TrustStore, MemoryVault]:
    """A process-wide store over an in-memory vault with a test root (no Touch ID)."""
    monkeypatch.setenv(trust.TEST_ROOT_ENV, "1")
    vault = MemoryVault()
    store = vault.store()
    trust.set_store(store)
    return store, vault


class Browser:
    """A browser's side of auth v2: a device key and the handshake."""

    def __init__(self, label: str = "Test browser", origin: str = "chrome-extension://abc") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.spki = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.label = label
        self.origin = origin
        self.session_key: bytes | None = None

    def sign(self, message: bytes) -> bytes:
        r, s = utils.decode_dss_signature(self.key.sign(message, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def hello(self, challenge: dict[str, Any]) -> tuple[dict[str, Any], x25519.X25519PrivateKey, str]:
        eph = x25519.X25519PrivateKey.generate()
        body = trust.body_text(
            {
                "v": 2,
                "nonce_s": challenge["nonce"],
                "nonce_c": trust.b64u(os.urandom(32)),
                "device_spki": trust.b64u(self.spki),
                "eph_c": trust.b64u(
                    eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                ),
                "label": self.label,
                "origin": self.origin,
            }
        )
        frame = {
            "type": "auth2_hello",
            "body": body,
            "sig": trust.b64u(self.sign(trust.CLIENT_CONTEXT + body.encode())),
        }
        return frame, eph, body

    def finish(self, ok: dict[str, Any], eph: x25519.X25519PrivateKey, hello_body: str) -> bytes:
        fields = json.loads(ok["body"])
        hermes_spki = trust.unb64u(fields["hermes_spki"])
        assert trust.verify(hermes_spki, trust.SERVER_CONTEXT + ok["body"].encode(), trust.unb64u(ok["sig"]))
        self.session_key = trust.session_key(eph, trust.unb64u(fields["eph_s"]), hello_body, ok["body"])
        return self.session_key

    async def connect(self, ws: Any, *, enroll: bool = True) -> dict[str, Any]:
        """Run the handshake on an aiohttp client socket; the final frame."""
        challenge = await receive(ws)
        frame, eph, body = self.hello(challenge)
        await ws.send_str(json.dumps(frame))
        reply = await receive(ws)
        if reply["type"] == "auth2_unendorsed" and enroll:
            await ws.send_str(json.dumps({"type": "device_enroll"}))
            reply = await receive(ws)
        if reply["type"] == "auth2_ok":
            self.finish(reply, eph, body)
        return reply


async def receive(ws: Any) -> dict[str, Any]:
    """The next frame other than a keepalive ping."""
    while True:
        frame: dict[str, Any] = json.loads((await asyncio.wait_for(ws.receive(), timeout=10)).data)
        if frame.get("type") != "ping":
            return frame
