"""Mordred Extension pairing — codes, ECDH key agreement, and attestation.

The pairing handshake is split across two processes:

- ``hermes mordred extension pair`` (CLI) generates a code, writes it to the
  shared pending-code store, and waits for the gateway to consume it.
- The gateway's extension WebSocket server (``extension_api.py``) receives the
  ``pair_init`` frame, validates the code, performs ECDH + HKDF to derive the
  shared AES key, signs the attestation challenge, issues an ``ext_token``,
  persists the pairing, and returns ``pair_complete``.

State lives under ``~/.hermes/extension/`` with ``0600`` permissions:

- ``pending.json``  — unconsumed pairing codes (CLI ⇄ gateway handoff).
- ``state.json``    — the active pairing (shared AES key, ext_token, pubkeys).
- ``attest_key.pem`` — the P-256 attestation key (TOFU-pinned by the extension).

See ``Mordred-Extension/SPEC.ja.md`` §3.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .extension_crypto import b64u_decode, b64u_encode, derive_shared_key, x25519_public_raw

# Unambiguous alphabet (no 0/O/1/I) — matches the extension and Hermes' own
# DM pairing (gateway/pairing.py).
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_TTL_SECONDS = 10 * 60
ATTEST_CONTEXT = b"mordred-ext-attest-v1"


class PairError(Exception):
    """Pairing rejected. ``reason`` is one of the SPEC pair_fail reasons."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def _ext_dir() -> Path:
    from hermes_constants import get_hermes_home

    d = get_hermes_home() / "extension"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _write_private(path: Path, data: bytes) -> None:
    # Write 0600, atomically where possible.
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}


# --------------------------------------------------------------------------- #
# Pairing code helpers
# --------------------------------------------------------------------------- #


def _format_code(raw16: str) -> str:
    return f"MORT-{raw16[:8]}-{raw16[8:16]}"


def normalize_code(code: str) -> str:
    """Canonicalize input to ``MORT-XXXXXXXX-XXXXXXXX`` (strip, upper).

    Strips a single leading ``MORT`` literal first (matching the extension's
    ``normalizeCode``) so its letters don't leak into the payload — otherwise
    ``M``/``R``/``T`` are valid alphabet chars and would shift the grouping."""
    upper = code.upper()
    if upper.startswith("MORT"):
        upper = upper[4:]
    cleaned = "".join(c for c in upper if c in _CODE_ALPHABET)
    return _format_code(cleaned[:16])


def generate_code() -> tuple[str, float]:
    """Create a pairing code, persist it as pending, return ``(code, expires_at)``."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(16))
    code = _format_code(raw)
    expires_at = time.time() + _CODE_TTL_SECONDS
    path = _ext_dir() / "pending.json"
    pending = _read_json(path)
    # Drop expired entries to keep the file bounded.
    now = time.time()
    pending = {k: v for k, v in pending.items() if v.get("expires_at", 0) > now}
    pending[code] = {"expires_at": expires_at, "used": False, "paired_at": None}
    _write_private(path, json.dumps(pending).encode("utf-8"))
    return code, expires_at


def _consume_code(code: str) -> None:
    """Validate a code against the pending store and mark it used. Raises PairError."""
    path = _ext_dir() / "pending.json"
    pending = _read_json(path)
    entry = pending.get(code)
    if entry is None:
        raise PairError("invalid_code")
    if entry.get("used"):
        raise PairError("already_used")
    if entry.get("expires_at", 0) < time.time():
        raise PairError("expired")
    entry["used"] = True
    entry["paired_at"] = time.time()
    pending[code] = entry
    _write_private(path, json.dumps(pending).encode("utf-8"))


def code_consumed(code: str) -> bool:
    """Has this code been consumed by a successful pair_init? (CLI polling)."""
    entry = _read_json(_ext_dir() / "pending.json").get(code)
    return bool(entry and entry.get("used"))


# --------------------------------------------------------------------------- #
# Attestation key (P-256) — persistent, TOFU-pinned by the extension
# --------------------------------------------------------------------------- #


def _load_or_create_attest_key() -> ec.EllipticCurvePrivateKey:
    path = _ext_dir() / "attest_key.pem"
    if path.exists():
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if isinstance(key, ec.EllipticCurvePrivateKey):
                return key
        except (ValueError, OSError):
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_private(path, pem)
    return key


def attest_pubkey_spki_b64() -> str:
    key = _load_or_create_attest_key()
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return b64u_encode(spki)


def _sign_attestation(challenge: bytes) -> str:
    """ECDSA-P256-SHA256 over ``ATTEST_CONTEXT || challenge``, returned as raw
    IEEE-P1363 (r‖s, 64 bytes) base64url — the format the extension verifies."""
    key = _load_or_create_attest_key()
    der = key.sign(ATTEST_CONTEXT + challenge, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


# --------------------------------------------------------------------------- #
# Secure-Enclave capability probe
# --------------------------------------------------------------------------- #


def se_available() -> bool:
    try:
        from mordred_hermes.keyvault import native

        return bool(native.is_secure_enclave_available())
    except Exception:  # noqa: BLE001 — non-macOS / keyvault absent → software keys
        return False


# --------------------------------------------------------------------------- #
# Active pairing state
# --------------------------------------------------------------------------- #


@dataclass
class Pairing:
    aes_key: bytes
    ext_token: str
    ext_pubkey_b64: str
    hermes_pubkey_b64: str
    paired_at: float


def _state_path() -> Path:
    return _ext_dir() / "state.json"


def load_pairing() -> Optional[Pairing]:
    data = _read_json(_state_path())
    if not data or "aes_key" not in data:
        return None
    return Pairing(
        aes_key=b64u_decode(data["aes_key"]),
        ext_token=data["ext_token"],
        ext_pubkey_b64=data.get("ext_pubkey", ""),
        hermes_pubkey_b64=data.get("hermes_pubkey", ""),
        paired_at=data.get("paired_at", 0.0),
    )


def _save_pairing(p: Pairing) -> None:
    _write_private(
        _state_path(),
        json.dumps(
            {
                "aes_key": b64u_encode(p.aes_key),
                "ext_token": p.ext_token,
                "ext_pubkey": p.ext_pubkey_b64,
                "hermes_pubkey": p.hermes_pubkey_b64,
                "paired_at": p.paired_at,
            }
        ).encode("utf-8"),
    )


def clear_pairing() -> None:
    for name in ("state.json",):
        with _suppress_oserror():
            (_ext_dir() / name).unlink()


class _suppress_oserror:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, *_: Any) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


def validate_token(ext_token: str) -> bool:
    p = load_pairing()
    if p is None or not ext_token:
        return False
    return secrets.compare_digest(p.ext_token, ext_token)


# --------------------------------------------------------------------------- #
# WebAuthn hardening (§3.5) — optional second factor at WS connect
# --------------------------------------------------------------------------- #


def _webauthn_path() -> Path:
    return _ext_dir() / "webauthn.json"


def has_webauthn_credential() -> bool:
    data = _read_json(_webauthn_path())
    return bool(data.get("credential_id") and data.get("public_key"))


def save_webauthn_credential(credential_id: str, public_key_b64: str) -> None:
    _write_private(
        _webauthn_path(),
        json.dumps({"credential_id": credential_id, "public_key": public_key_b64}).encode("utf-8"),
    )


def clear_webauthn_credential() -> None:
    with _suppress_oserror():
        _webauthn_path().unlink()


def verify_webauthn_assertion(nonce: bytes, assertion: dict[str, Any]) -> bool:
    """Verify a WebAuthn assertion over ``nonce`` against the stored credential.

    Checks: the credential id matches, clientDataJSON is a ``webauthn.get`` whose
    challenge equals ``nonce``, the user-verified flag is set, and the ECDSA
    P-256 signature over ``authenticatorData || SHA256(clientDataJSON)`` is valid.
    """
    import hashlib
    import json as _json

    data = _read_json(_webauthn_path())
    stored_id = data.get("credential_id")
    pub_b64 = data.get("public_key")
    if not stored_id or not pub_b64:
        return False
    if assertion.get("credential_id") != stored_id:
        return False

    try:
        client_data_raw = b64u_decode(assertion["client_data_json"])
        auth_data = b64u_decode(assertion["authenticator_data"])
        signature = b64u_decode(assertion["signature"])
    except Exception:  # noqa: BLE001
        return False

    try:
        client = _json.loads(client_data_raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return False
    if client.get("type") != "webauthn.get":
        return False
    if client.get("challenge") != b64u_encode(nonce):
        return False
    # User-verified (UV) flag must be set (bit 2 of the flags byte at offset 32).
    if len(auth_data) < 37 or not (auth_data[32] & 0x04):
        return False

    try:
        pub = serialization.load_der_public_key(b64u_decode(pub_b64))
        signed = auth_data + hashlib.sha256(client_data_raw).digest()
        pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# pair_init handler (gateway side)
# --------------------------------------------------------------------------- #


def handle_pair_init(code: str, ext_pubkey_b64: str, challenge_b64: str) -> dict[str, Any]:
    """Validate the code, derive the shared key, persist the pairing, and return
    the ``pair_complete`` payload. Raises :class:`PairError` on rejection."""
    code = normalize_code(code)
    _consume_code(code)  # raises on invalid/expired/used

    try:
        challenge = b64u_decode(challenge_b64)
    except Exception as exc:  # noqa: BLE001
        raise PairError("invalid_challenge") from exc
    if len(challenge) < 16:
        raise PairError("invalid_challenge")

    hermes_priv = X25519PrivateKey.generate()
    try:
        aes_key = derive_shared_key(hermes_priv, ext_pubkey_b64, code)
    except Exception as exc:  # noqa: BLE001 — bad ext pubkey
        raise PairError("invalid_pubkey") from exc

    hermes_pub_b64 = b64u_encode(x25519_public_raw(hermes_priv))
    ext_token = b64u_encode(secrets.token_bytes(32))

    _save_pairing(
        Pairing(
            aes_key=aes_key,
            ext_token=ext_token,
            ext_pubkey_b64=ext_pubkey_b64,
            hermes_pubkey_b64=hermes_pub_b64,
            paired_at=time.time(),
        )
    )

    return {
        "hermes_pubkey": hermes_pub_b64,
        "ext_token": ext_token,
        "attestation": {
            "signed_challenge": _sign_attestation(challenge),
            "se_pubkey": attest_pubkey_spki_b64(),
            "se_available": se_available(),
        },
    }
