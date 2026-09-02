"""Internal WebAuthn credential storage and assertion verification.

The public compatibility surface remains
:mod:`mordred_hermes.extension.pairing`; that module re-exports the functions
defined here.  Storage primitives are resolved through the pairing module so
existing callers and tests that replace its filesystem helpers keep working.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import SplitResult, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import b64u_decode, b64u_encode

if TYPE_CHECKING:
    from .pairing import Pairing


class InvalidWebAuthnPublicKey(ValueError):
    """A registration key is malformed or outside the supported ES256 suite."""


def _webauthn_path() -> Path:
    from . import pairing

    return pairing._ext_dir() / "webauthn.json"


def _pairing_token_hash(token: str) -> str:
    return b64u_encode(hashlib.sha256(token.encode("utf-8")).digest())


def _active_webauthn_data(active: Pairing | None = None) -> dict[str, Any]:
    """Return only the credential bound to the active pairing generation."""
    from . import pairing

    if active is None:
        active = pairing.load_pairing()
    if active is None:
        return {}
    data = pairing._read_json(_webauthn_path())
    if not data:
        return {}
    bound_token_hash = data.get("pairing_token_hash")
    if isinstance(bound_token_hash, str):
        return data if secrets.compare_digest(bound_token_hash, _pairing_token_hash(active.ext_token)) else {}
    state = pairing._read_state_cached()
    # Backward compatibility: pre-upgrade credentials had no token binding.
    # A new pairing writes this marker, so those records cannot cross a re-pair.
    return {} if state.get("reject_unbound_webauthn") is True else data


def has_webauthn_credential() -> bool:
    data = _active_webauthn_data()
    return bool(data.get("credential_id") and data.get("public_key"))


def authentication_generation_fingerprint(
    expected_ext_token: str | None = None,
) -> bytes | None:
    """Fingerprint the complete principal state used by extension auth.

    The pairing token/key generation and WebAuthn credential generation both
    participate. Open sockets compare this value before every privileged
    frame, so re-pair, unpair, credential registration, and credential removal
    all revoke sessions authenticated against the previous state.

    When ``expected_ext_token`` is supplied, return ``None`` unless it is still
    the active token. This lets authentication bind the token check and the
    generation snapshot to the same disk read.
    """
    try:
        from . import pairing

        active = pairing.load_pairing()
        if active is None or not isinstance(active.ext_token, str):
            return None
        if expected_ext_token is not None and not secrets.compare_digest(
            active.ext_token.encode("utf-8"),
            expected_ext_token.encode("utf-8"),
        ):
            return None
        webauthn = _active_webauthn_data(active)
        material = {
            "pairing": {
                "aes_key": b64u_encode(active.aes_key),
                "ext_token": active.ext_token,
                "ext_pubkey": active.ext_pubkey_b64,
                "hermes_pubkey": active.hermes_pubkey_b64,
                "paired_at": active.paired_at,
            },
            "webauthn": {
                field: webauthn.get(field)
                for field in (
                    "credential_id",
                    "public_key",
                    "pairing_token_hash",
                    "origin",
                    "transport_origin",
                    "rp_id",
                    "rp_id_hash",
                )
            },
        }
        canonical = json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).digest()
    except Exception:
        return None


def _parse_extension_origin(origin: str, *, scheme: str | None = None) -> SplitResult | None:
    """Parse ``origin`` and return it only if it is a bare extension origin.

    A bare origin is ``chrome-extension://`` or ``moz-extension://`` (or exactly
    ``scheme`` when given) followed by a host and nothing else: no userinfo, no
    port, no path/query/fragment. Those extras are the lookalike shapes an
    attacker would use to smuggle a foreign origin past a prefix check, so every
    extension-origin gate in this package funnels through here. Returns ``None``
    for anything else, including a value ``urlsplit`` (or ``.port``) rejects.
    """
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme not in {"chrome-extension", "moz-extension"}
        or (scheme is not None and parsed.scheme != scheme)
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    return parsed


def _rp_id_for_origin(origin: str) -> str | None:
    """Derive Chromium's effective RP ID for its default extension ceremony.

    Chromium initially defaults the claimed RP ID to the extension id (the
    origin host), then maps it to the serialized ``chrome-extension://``
    origin before talking to the authenticator.  Consequently ``rpIdHash`` is
    SHA-256 over the *full origin*, not just the extension id.

    Firefox uses a stable WebAuthn origin that differs from the random
    ``moz-extension://`` document/WebSocket origin and does not allow that
    document origin as an RP ID.  The current registration message carries
    neither Firefox's stable ceremony origin nor an external RP ID, so Firefox
    registration must remain unsupported rather than persisting a binding that
    can never verify.
    """
    parsed = _parse_extension_origin(origin, scheme="chrome-extension")
    if parsed is None:
        return None
    return f"chrome-extension://{parsed.hostname}"


def _load_p256_public_key(public_key_b64: str) -> ec.EllipticCurvePublicKey:
    """Decode a stored WebAuthn ES256 key and enforce its P-256 curve.

    Deliberately stricter than the pre-split verifier, which accepted any
    EC curve: WebAuthn ES256 (COSE alg -7) is defined over P-256, and
    :func:`save_webauthn_credential` validates new registrations through
    this same gate. A legacy credential on another curve — storable only
    by a non-standard client, since the extension requests ES256 — now
    fails verification (fail closed). Recovery: delete
    ``~/.hermes/extension/webauthn.json`` and re-register the credential
    (accepted narrowing, review 2026-07-29).
    """
    try:
        public_key = serialization.load_der_public_key(b64u_decode(public_key_b64))
    except Exception as exc:
        raise InvalidWebAuthnPublicKey("invalid WebAuthn public key") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve,
        ec.SECP256R1,
    ):
        raise InvalidWebAuthnPublicKey("WebAuthn public key must use EC P-256")
    return public_key


def save_webauthn_credential(
    credential_id: str,
    public_key_b64: str,
    *,
    origin: str | None = None,
) -> None:
    from . import pairing

    # Validate before taking the state lock or replacing a working credential.
    _load_p256_public_key(public_key_b64)
    body: dict[str, str] = {
        "credential_id": credential_id,
        "public_key": public_key_b64,
    }
    if origin is not None:
        rp_id = _rp_id_for_origin(origin)
        if rp_id is None:
            raise ValueError(f"invalid WebAuthn origin: {origin!r}")
        body["origin"] = origin
        body["transport_origin"] = origin
        body["rp_id"] = rp_id
        body["rp_id_hash"] = b64u_encode(hashlib.sha256(rp_id.encode("utf-8")).digest())
    with pairing._state_lock():
        state = pairing._read_state_cached()
        active_token = state.get("ext_token")
        if not isinstance(active_token, str) or not active_token:
            raise ValueError("active pairing required before WebAuthn registration")
        body["pairing_token_hash"] = _pairing_token_hash(active_token)
        pairing._write_private(
            _webauthn_path(),
            json.dumps(body).encode("utf-8"),
        )


def clear_webauthn_credential() -> None:
    from . import pairing

    with pairing._state_lock(), pairing._suppress_oserror():
        _webauthn_path().unlink()


def _decode_webauthn_fields(assertion: dict[str, Any]) -> tuple[bytes, bytes, bytes] | None:
    """b64u-decode ``(clientDataJSON, authenticatorData, signature)`` from an
    assertion payload, or ``None`` if any field is missing or malformed."""
    try:
        return (
            b64u_decode(assertion["client_data_json"]),
            b64u_decode(assertion["authenticator_data"]),
            b64u_decode(assertion["signature"]),
        )
    except Exception:
        return None


def _parse_client_data(client_data_raw: bytes) -> dict[str, Any] | None:
    """Parse the signed clientDataJSON object without trusting its fields."""
    try:
        value = json.loads(client_data_raw.decode("utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _client_data_matches(client_data_raw: bytes, nonce: bytes, expected_origin: str) -> bool:
    """True iff ``clientDataJSON`` parses as a ``webauthn.get`` whose challenge
    equals ``nonce`` and whose ceremony is bound to the expected origin."""
    client = _parse_client_data(client_data_raw)
    if client is None:
        return False
    if client.get("type") != "webauthn.get":
        return False
    if client.get("challenge") != b64u_encode(nonce):
        return False
    if client.get("origin") != expected_origin:
        return False
    return client.get("crossOrigin", False) is False


def _signature_valid(pub_b64: str, auth_data: bytes, client_data_raw: bytes, signature: bytes) -> bool:
    """True iff ``signature`` is a valid ES256 signature by the stored public
    key over ``authenticatorData || SHA256(clientDataJSON)``."""
    try:
        pub = _load_p256_public_key(pub_b64)
        signed = auth_data + hashlib.sha256(client_data_raw).digest()
        pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _serialized_extension_origin(origin: str, *, scheme: str | None = None) -> str | None:
    """Return an exact canonical extension origin, or ``None``."""
    parsed = _parse_extension_origin(origin, scheme=scheme)
    if parsed is None:
        return None
    canonical = f"{parsed.scheme}://{parsed.hostname}"
    return canonical if origin == canonical else None


def _stored_webauthn_binding(
    data: dict[str, Any],
    expected_transport_origin: str | None,
) -> tuple[str, bytes] | None:
    """Resolve the stored ceremony origin and exact authenticator RP hash."""
    stored_origin = data.get("origin")
    if not isinstance(stored_origin, str) or _serialized_extension_origin(stored_origin) is None:
        return None

    stored_transport = data.get("transport_origin")
    if not isinstance(stored_transport, str):
        # Chrome's ceremony and WebSocket document origins are identical.
        stored_transport = stored_origin if stored_origin.startswith("chrome-extension://") else None
    if stored_transport is None or _serialized_extension_origin(stored_transport) is None:
        return None
    if expected_transport_origin is None:
        expected_transport_origin = stored_transport
    if expected_transport_origin != stored_transport:
        return None

    encoded_hash = data.get("rp_id_hash")
    if isinstance(encoded_hash, str):
        try:
            rp_hash = b64u_decode(encoded_hash)
        except Exception:
            return None
        if len(rp_hash) != 32:
            return None
    else:
        stored_rp_id = data.get("rp_id")
        if not isinstance(stored_rp_id, str) or not stored_rp_id:
            return None
        rp_hash = hashlib.sha256(stored_rp_id.encode("utf-8")).digest()
    return stored_origin, rp_hash


def _authenticator_data_matches(auth_data: bytes, expected_rp_hash: bytes) -> bool:
    """Validate RP binding plus user-presence and verification flags."""
    if len(auth_data) < 37:
        return False
    if not secrets.compare_digest(auth_data[:32], expected_rp_hash):
        return False
    flags = auth_data[32]
    return bool(flags & 0x01 and flags & 0x04)


def _legacy_client_origins(
    *,
    expected_transport_origin: str | None,
    nonce: bytes,
    client_data_raw: bytes,
) -> tuple[str, str, str] | None:
    """Validate signed client data and return transport/ceremony/scheme."""
    if expected_transport_origin is None:
        return None
    transport_origin = _serialized_extension_origin(expected_transport_origin)
    client = _parse_client_data(client_data_raw)
    if transport_origin is None or client is None:
        return None
    ceremony_origin = client.get("origin")
    if not isinstance(ceremony_origin, str):
        return None
    transport_scheme = urlsplit(transport_origin).scheme
    ceremony_origin = _serialized_extension_origin(ceremony_origin, scheme=transport_scheme)
    if ceremony_origin is None:
        return None
    if (
        client.get("type") != "webauthn.get"
        or client.get("challenge") != b64u_encode(nonce)
        or client.get("crossOrigin", False) is not False
    ):
        return None
    return transport_origin, ceremony_origin, transport_scheme


def _legacy_signed_rp_hash(
    data: dict[str, Any],
    *,
    client_data_raw: bytes,
    auth_data: bytes,
    signature: bytes,
) -> bytes | None:
    """Return the authenticator's signed RP hash after UP/UV verification."""
    if len(auth_data) < 37 or not (auth_data[32] & 0x01 and auth_data[32] & 0x04):
        return None
    if not _signature_valid(str(data["public_key"]), auth_data, client_data_raw, signature):
        return None
    return auth_data[:32]


def _persist_legacy_webauthn_binding(
    data: dict[str, Any],
    *,
    transport_origin: str,
    ceremony_origin: str,
    rp_hash: bytes,
    rp_id: str | None,
) -> bool:
    """Persist an assertion-proven binding if the credential stayed unchanged."""
    from . import pairing

    body = dict(data)
    body.update(
        {
            "origin": ceremony_origin,
            "transport_origin": transport_origin,
            "rp_id_hash": b64u_encode(rp_hash),
        }
    )
    if rp_id is None:
        body.pop("rp_id", None)
    else:
        body["rp_id"] = rp_id
    try:
        with pairing._state_lock():
            current = pairing._read_json(_webauthn_path())
            binding_fields = ("origin", "transport_origin", "rp_id", "rp_id_hash")
            unchanged = (
                current.get("credential_id") == data.get("credential_id")
                and current.get("public_key") == data.get("public_key")
                and not any(field in current for field in binding_fields)
            )
            state = pairing._read_state_cached()
            active_token = state.get("ext_token")
            if not unchanged or not isinstance(active_token, str) or not active_token:
                return False
            body["pairing_token_hash"] = _pairing_token_hash(active_token)
            pairing._write_private(_webauthn_path(), json.dumps(body).encode("utf-8"))
        return True
    except Exception:
        return False


def _migrate_legacy_webauthn_binding(
    data: dict[str, Any],
    *,
    expected_transport_origin: str | None,
    nonce: bytes,
    client_data_raw: bytes,
    auth_data: bytes,
    signature: bytes,
) -> bool:
    """Bind a pre-origin credential using a fresh, fully signed assertion.

    Firefox's signed ceremony origin differs from its document/WebSocket
    origin, so both origins and the authenticator's RP hash are retained.
    """
    origins = _legacy_client_origins(
        expected_transport_origin=expected_transport_origin,
        nonce=nonce,
        client_data_raw=client_data_raw,
    )
    rp_hash = _legacy_signed_rp_hash(
        data,
        client_data_raw=client_data_raw,
        auth_data=auth_data,
        signature=signature,
    )
    if origins is None or rp_hash is None:
        return False
    transport_origin, ceremony_origin, transport_scheme = origins

    rp_id: str | None = None
    if transport_scheme == "chrome-extension":
        # Chromium uses one origin for both surfaces and maps its RP ID to that
        # full serialized origin. Do not accept a legacy assertion that says
        # otherwise.
        if ceremony_origin != transport_origin:
            return False
        rp_id = _rp_id_for_origin(ceremony_origin)
        if rp_id is None or not secrets.compare_digest(
            rp_hash,
            hashlib.sha256(rp_id.encode("utf-8")).digest(),
        ):
            return False
    return _persist_legacy_webauthn_binding(
        data,
        transport_origin=transport_origin,
        ceremony_origin=ceremony_origin,
        rp_hash=rp_hash,
        rp_id=rp_id,
    )


def verify_webauthn_assertion(
    nonce: bytes,
    assertion: dict[str, Any],
    *,
    expected_origin: str | None = None,
) -> bool:
    """Verify a WebAuthn assertion over ``nonce`` against the stored credential.

    Checks: credential id, challenge, origin, cross-origin status, RP ID hash,
    user-presence/user-verification flags, and the ECDSA P-256 signature.
    Every failure path returns ``False`` (fail-closed).
    """
    data = _active_webauthn_data()
    stored_id = data.get("credential_id")
    pub_b64 = data.get("public_key")
    if not stored_id or not pub_b64:
        return False
    if assertion.get("credential_id") != stored_id:
        return False
    fields = _decode_webauthn_fields(assertion)
    if fields is None:
        return False
    client_data_raw, auth_data, signature = fields

    binding = _stored_webauthn_binding(data, expected_origin)
    if binding is None:
        is_legacy = not any(
            field in data
            for field in (
                "origin",
                "transport_origin",
                "rp_id",
                "rp_id_hash",
            )
        )
        return is_legacy and _migrate_legacy_webauthn_binding(
            data,
            expected_transport_origin=expected_origin,
            nonce=nonce,
            client_data_raw=client_data_raw,
            auth_data=auth_data,
            signature=signature,
        )
    ceremony_origin, expected_rp_hash = binding

    if not _client_data_matches(client_data_raw, nonce, ceremony_origin):
        return False
    if not _authenticator_data_matches(auth_data, expected_rp_hash):
        return False

    return _signature_valid(pub_b64, auth_data, client_data_raw, signature)
