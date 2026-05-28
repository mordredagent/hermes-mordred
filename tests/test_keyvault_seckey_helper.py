"""Cross-platform tests for the subprocess Secure-Enclave helper bridge.

These exercise ``mordred_hermes.keyvault._seckey_helper`` without any real
Secure Enclave: a stateful *fake helper* script (real software P-256 via
``cryptography``, persisted to a temp JSON store) speaks the exact
JSON-over-stdio protocol the signed Swift binary implements. So the whole
bridge — subprocess spawn, JSON framing, hex (de)coding, ``_OpsError``
mapping, and the ``_SecKeyBackend`` wiring — runs on Linux CI too.

The signed Swift binary itself is covered only by the live integration test
(``tests/integration/test_keyvault_macos.py``, ``MORDRED_KEYVAULT_LIVE=1``).
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.keyvault import _seckey_helper
from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
from mordred_hermes.keyvault._seckey_backend import (
    _application_tag,
    _OpsError,
    _SecKeyBackend,
    _translate_error,
    errSecDuplicateItem,
    errSecItemNotFound,
)
from mordred_hermes.keyvault._seckey_helper import (
    _HELPER_NAME,
    _find_helper,
    _HelperSecKeyOps,
    _run_helper,
)

# ---------------------------------------------------------------------------
# Fake helper: a real-crypto software stand-in for the signed Swift binary.
# ---------------------------------------------------------------------------

# Mirrors the JSON-over-stdio contract in native/sekey-helper/README.md.
# Errors use the SAME OSStatus ints as the real helper so _translate_error
# behaves identically. State (keys) lives in $FAKE_SEKEY_STORE so a
# generate→public_key→ecdh→delete sequence works across separate invocations.
_FAKE_HELPER_BODY = r'''
import json, os, sys

def err(status, domain="OSStatus", message="fake error"):
    print(json.dumps({"error": {"domain": domain, "status": int(status), "message": message}}))
    sys.exit(1)

mode = os.environ.get("FAKE_MODE", "")
if mode == "nonzero_no_error":
    sys.exit(3)
if mode == "garbage":
    sys.stdout.write("this is not json")
    sys.exit(0)
if mode == "hang":
    import time
    time.sleep(30)

raw = sys.stdin.read()
try:
    req = json.loads(raw)
except Exception:
    err(-1, "helper", "bad json on stdin")

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_der_private_key,
)

store_path = os.environ["FAKE_SEKEY_STORE"]
store = {}
if os.path.exists(store_path):
    with open(store_path) as f:
        store = json.load(f)

def save():
    with open(store_path, "w") as f:
        json.dump(store, f)

cmd = req.get("cmd")
tag = req.get("tag_hex")

if cmd == "generate":
    if tag in store:
        err(-25299, message="duplicate item")
    priv = ec.generate_private_key(ec.SECP256R1())
    store[tag] = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()).hex()
    save()
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    print(json.dumps({"public_key_hex": pub.hex()}))
elif cmd == "public_key":
    if tag not in store:
        err(-25300, message="item not found")
    priv = load_der_private_key(bytes.fromhex(store[tag]), password=None)
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    print(json.dumps({"public_key_hex": pub.hex()}))
elif cmd == "delete":
    store.pop(tag, None)
    save()
    print(json.dumps({"ok": True}))
elif cmd == "ecdh":
    if tag not in store:
        err(-25300, message="item not found")
    priv = load_der_private_key(bytes.fromhex(store[tag]), password=None)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(req["peer_pub_hex"])
    )
    shared = priv.exchange(ec.ECDH(), peer)
    print(json.dumps({"shared_hex": shared.hex()}))
elif cmd == "probe":
    print(json.dumps({"ok": True}))
else:
    err(-1, "helper", "unknown cmd")
'''


@pytest.fixture
def fake_helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Write an executable fake helper and point the bridge at it.

    Uses the current interpreter in the shebang so the subprocess inherits
    the venv (where ``cryptography`` is installed).
    """
    script = tmp_path / "fake-sekey"
    script.write_text(f"#!{sys.executable}\n{_FAKE_HELPER_BODY}")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    store = tmp_path / "store.json"
    monkeypatch.setenv("FAKE_SEKEY_STORE", str(store))
    monkeypatch.setenv("MORDRED_SEKEY_HELPER", str(script))
    return str(script)


def _x962(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


# ---------------------------------------------------------------------------
# _find_helper resolution order
# ---------------------------------------------------------------------------


def test_find_helper_env_authoritative_when_file_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "helper"
    target.write_text("#!/bin/sh\n")
    monkeypatch.setenv("MORDRED_SEKEY_HELPER", str(target))
    assert _find_helper() == str(target)


def test_find_helper_env_missing_returns_none_not_fallthrough(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # env set but the target does not exist → None (do NOT fall through to
    # ~/.local/bin or PATH; a typo must surface as "no helper").
    monkeypatch.setenv("MORDRED_SEKEY_HELPER", str(tmp_path / "nonexistent"))
    monkeypatch.setattr(_seckey_helper.shutil, "which", lambda _name: "/usr/bin/should-not-be-used")
    assert _find_helper() is None


def test_find_helper_local_bin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MORDRED_SEKEY_HELPER", raising=False)
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    binary = home / ".local" / "bin" / _HELPER_NAME
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(_seckey_helper.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(_seckey_helper.shutil, "which", lambda _name: None)
    assert _find_helper() == str(binary)


def test_find_helper_path_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MORDRED_SEKEY_HELPER", raising=False)
    monkeypatch.setattr(_seckey_helper.Path, "home", classmethod(lambda _cls: tmp_path / "empty-home"))
    monkeypatch.setattr(_seckey_helper.shutil, "which", lambda name: "/opt/bin/" + name)
    assert _find_helper() == "/opt/bin/" + _HELPER_NAME


def test_find_helper_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MORDRED_SEKEY_HELPER", raising=False)
    monkeypatch.setattr(_seckey_helper.Path, "home", classmethod(lambda _cls: tmp_path / "empty-home"))
    monkeypatch.setattr(_seckey_helper.shutil, "which", lambda _name: None)
    assert _find_helper() is None


# ---------------------------------------------------------------------------
# _HelperSecKeyOps happy paths (real subprocess + real crypto)
# ---------------------------------------------------------------------------


def test_generate_public_key_delete_roundtrip(fake_helper: str) -> None:
    ops = _HelperSecKeyOps(fake_helper)
    tag = b"mordred-hermes.wrap.test-tag-aaaa"

    pub = ops.create_keypair(tag, "label")
    assert len(pub) == 65 and pub[:1] == b"\x04"

    # public_key returns the same key.
    assert ops.copy_public_key(tag) == pub

    ops.delete_key(tag)
    # After delete the key is gone.
    with pytest.raises(_OpsError) as exc:
        ops.copy_public_key(tag)
    assert exc.value.status == errSecItemNotFound


def test_ecdh_agrees_with_local_peer(fake_helper: str) -> None:
    ops = _HelperSecKeyOps(fake_helper)
    tag = b"mordred-hermes.wrap.test-tag-bbbb"

    enclave_pub_bytes = ops.create_keypair(tag, "label")
    enclave_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), enclave_pub_bytes)

    peer_priv = ec.generate_private_key(ec.SECP256R1())
    shared_helper = ops.key_exchange(tag, _x962(peer_priv.public_key()))
    shared_local = peer_priv.exchange(ec.ECDH(), enclave_pub)

    assert shared_helper == shared_local
    assert len(shared_helper) == 32


def test_delete_is_idempotent(fake_helper: str) -> None:
    ops = _HelperSecKeyOps(fake_helper)
    # Deleting a never-created tag does not raise.
    ops.delete_key(b"mordred-hermes.wrap.never-existed")


def test_probe_succeeds(fake_helper: str) -> None:
    _HelperSecKeyOps(fake_helper).probe()  # no raise


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def test_error_json_maps_to_opserror_with_raw_status(fake_helper: str) -> None:
    ops = _HelperSecKeyOps(fake_helper)
    with pytest.raises(_OpsError) as exc:
        ops.key_exchange(b"missing-tag", b"\x04" + b"\x00" * 64)
    assert exc.value.status == errSecItemNotFound
    assert exc.value.domain == "OSStatus"
    # The existing taxonomy must classify it as key_not_found.
    assert _translate_error(exc.value.status, exc.value.domain) == "key_not_found"


def test_duplicate_generate_maps_to_duplicate_status(fake_helper: str) -> None:
    ops = _HelperSecKeyOps(fake_helper)
    tag = b"mordred-hermes.wrap.dup-tag"
    ops.create_keypair(tag, "label")
    with pytest.raises(_OpsError) as exc:
        ops.create_keypair(tag, "label")
    assert exc.value.status == errSecDuplicateItem


def test_nonzero_exit_without_error_object(fake_helper: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_MODE", "nonzero_no_error")
    with pytest.raises(_OpsError) as exc:
        _run_helper(fake_helper, {"cmd": "probe"})
    assert exc.value.domain == "helper"


def test_non_json_output(fake_helper: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_MODE", "garbage")
    with pytest.raises(_OpsError) as exc:
        _run_helper(fake_helper, {"cmd": "probe"})
    assert exc.value.domain == "helper"


def test_timeout(fake_helper: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_MODE", "hang")
    monkeypatch.setattr(_seckey_helper, "_TIMEOUT_SECONDS", 0.5)
    with pytest.raises(_OpsError) as exc:
        _run_helper(fake_helper, {"cmd": "probe"})
    assert "timed out" in str(exc.value)


def test_spawn_failure_when_binary_missing() -> None:
    with pytest.raises(_OpsError) as exc:
        _run_helper("/nonexistent/path/to/helper", {"cmd": "probe"})
    assert exc.value.domain == "helper"


# ---------------------------------------------------------------------------
# _SecKeyBackend wiring through the helper ops
# ---------------------------------------------------------------------------


def test_backend_generate_get_delete_via_helper(fake_helper: str) -> None:
    backend = _SecKeyBackend(ops=_HelperSecKeyOps(fake_helper))
    key_id = "wiring-test-key"

    pub = backend.generate_enclave_key(key_id)
    assert len(pub) == 65

    assert backend.get_enclave_public_key(key_id) == pub

    backend.delete_enclave_key(key_id)
    with pytest.raises(WrapKeyNotFound):
        backend.get_enclave_public_key(key_id)


def test_backend_uses_application_tag(fake_helper: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # The backend must hand the helper the hashed application tag, never the
    # cleartext key_id (POLICY.md #19).
    ops = _HelperSecKeyOps(fake_helper)
    seen: list[str] = []
    real_run = _seckey_helper._run_helper

    def _spy(binary: str, payload: dict) -> dict:
        if "tag_hex" in payload:
            seen.append(payload["tag_hex"])
        return real_run(binary, payload)

    monkeypatch.setattr(_seckey_helper, "_run_helper", _spy)
    backend = _SecKeyBackend(ops=ops)
    key_id = "tag-derivation-key"
    backend.generate_enclave_key(key_id)

    assert seen, "helper was never called with a tag"
    assert all(t == _application_tag(key_id).hex() for t in seen)
    assert key_id.encode().hex() not in seen[0]
