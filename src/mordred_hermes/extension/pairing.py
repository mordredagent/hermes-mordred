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
- ``webauthn.json`` — the optional credential managed by :mod:`.webauthn`.

WebAuthn operations remain available from this module for compatibility, while
their credential binding and assertion verification live in :mod:`.webauthn`.

See ``Mordred-Extension/SPEC.ja.md`` §3.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeGuard

try:
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX platform
    fcntl = None  # type: ignore[assignment]

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..keyvault._storage import atomic_write
from .crypto import b64u_decode, b64u_encode, derive_shared_key, x25519_public_raw
from .webauthn import (
    _active_webauthn_data as _active_webauthn_data,
)
from .webauthn import (
    _authenticator_data_matches as _authenticator_data_matches,
)
from .webauthn import (
    _client_data_matches as _client_data_matches,
)
from .webauthn import (
    _decode_webauthn_fields as _decode_webauthn_fields,
)
from .webauthn import (
    _legacy_client_origins as _legacy_client_origins,
)
from .webauthn import (
    _legacy_signed_rp_hash as _legacy_signed_rp_hash,
)
from .webauthn import (
    _migrate_legacy_webauthn_binding as _migrate_legacy_webauthn_binding,
)
from .webauthn import (
    _pairing_token_hash as _pairing_token_hash,
)
from .webauthn import (
    _parse_client_data as _parse_client_data,
)
from .webauthn import (
    _persist_legacy_webauthn_binding as _persist_legacy_webauthn_binding,
)
from .webauthn import (
    _rp_id_for_origin as _rp_id_for_origin,
)
from .webauthn import (
    _serialized_extension_origin as _serialized_extension_origin,
)
from .webauthn import (
    _signature_valid as _signature_valid,
)
from .webauthn import (
    _stored_webauthn_binding as _stored_webauthn_binding,
)
from .webauthn import (
    _webauthn_path as _webauthn_path,
)
from .webauthn import (
    authentication_generation_fingerprint as authentication_generation_fingerprint,
)
from .webauthn import (
    clear_webauthn_credential as clear_webauthn_credential,
)
from .webauthn import (
    has_webauthn_credential as has_webauthn_credential,
)
from .webauthn import (
    save_webauthn_credential as save_webauthn_credential,
)
from .webauthn import (
    verify_webauthn_assertion as verify_webauthn_assertion,
)

# Unambiguous alphabet (no 0/O/1/I) — matches the extension and Hermes' own
# DM pairing (gateway/pairing.py).
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_TTL_SECONDS = 10 * 60
ATTEST_CONTEXT = b"mordred-ext-attest-v1"
_E2E_REPLAY_FIELD = "e2e_replay_v3"
_E2E_REPLAY_TTL_SECONDS = 30 * 24 * 3600
# Two identities are stored per accepted platform message. Capping at 32K
# keeps the JSON rewrite bounded while retaining the most recent 16K commands.
_E2E_REPLAY_MAX_IDENTITIES = 32_768


class PairError(Exception):
    """Pairing rejected. ``reason`` is one of the SPEC pair_fail reasons."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def _ext_dir() -> Path:
    from .._home import hermes_home

    d = hermes_home() / "extension"
    d.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(d, 0o700)
    return d


def _write_private(path: Path, data: bytes) -> None:
    """0600 atomic write, delegated to the keyvault's canonical helper.

    These files hold the pairing AES key, the ext_token and the attestation
    private key — the same class of secret the keyvault protects — so they get
    the same guarantees instead of a hand-rolled, weaker copy: unpredictable tmp
    name, ``O_EXCL | O_NOFOLLOW`` (no symlink follow / tmp pre-planting), fsync
    of the tmp fd *and* the parent dir, and tmp cleanup on failure. The parent
    directory always exists here — every caller resolves its path through
    :func:`_ext_dir`, which mkdirs it."""
    atomic_write(path, data)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


@contextlib.contextmanager
def _state_lock() -> Iterator[None]:
    """Cross-process mutex for read-modify-write cycles on the JSON stores.

    The CLI (``extension pair``) and the gateway server mutate ``pending.json``
    / ``state.json`` from different processes; without this, interleaved
    read→write cycles lose updates — e.g. two racing ``pair_init`` frames could
    both consume the same one-time code. Locked sections must stay synchronous
    (no awaits): callers run on the gateway's event loop and rely on the lock
    being held only for a quick file round-trip.
    """
    if fcntl is None:  # non-POSIX fallback: single-process best effort
        yield
        return
    fd = os.open(_ext_dir() / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


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
    with _state_lock():
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
    # The lock spans check + mark-used: without it two racing pair_init frames
    # could both see used=False and pair against the same one-time code.
    with _state_lock():
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
    """Has this code been claimed by a pair_init attempt? (legacy CLI polling).

    Claimed ≠ paired: the handshake can still fail after the code is consumed.
    Prefer :func:`pair_outcome`, which distinguishes the two; this stays for
    older CLI builds and the Hermes-fork gateway's identical pending.json."""
    entry = _read_json(_ext_dir() / "pending.json").get(code)
    return bool(entry and entry.get("used"))


def _mark_pair_result(code: str, result: str, fail_reason: str | None = None) -> None:
    """Record the pair_init outcome on the consumed pending entry.

    The polling CLI reads this back via :func:`pair_outcome`; without it a
    handshake that dies *after* claiming the code is indistinguishable from a
    successful pairing. Additive fields only — servers that predate them (the
    Hermes-fork gateway) simply never write a result."""
    path = _ext_dir() / "pending.json"
    with _state_lock():
        pending = _read_json(path)
        entry = pending.get(code)
        if entry is None:  # pruned meanwhile — nothing to annotate
            return
        entry["result"] = result
        if fail_reason is not None:
            entry["fail_reason"] = fail_reason
        pending[code] = entry
        _write_private(path, json.dumps(pending).encode("utf-8"))


def pair_outcome(code: str) -> tuple[str, str | None]:
    """CLI polling: ``(state, fail_reason)``.

    ``state`` is one of:

    - ``"pending"``  — not claimed yet.
    - ``"paired"``   — handshake completed and the pairing was persisted.
    - ``"failed"``   — claimed, then rejected; ``fail_reason`` is the SPEC
      pair_fail reason. The code stays burned (single-use).
    - ``"consumed"`` — claimed with no outcome recorded: mid-handshake, or a
      server implementation that predates result recording.
    """
    entry = _read_json(_ext_dir() / "pending.json").get(code)
    if not entry or not entry.get("used"):
        return ("pending", None)
    result = entry.get("result")
    if result == "paired":
        return ("paired", None)
    if result == "failed":
        return ("failed", entry.get("fail_reason") or "unknown")
    return ("consumed", None)


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
    except Exception:
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


def load_pairing() -> Pairing | None:
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
    # Preserve any v2 keyring fields (channel_keys) already in state.
    with _state_lock():
        data = _read_json(_state_path()) or {}
        data.update(
            {
                "aes_key": b64u_encode(p.aes_key),
                "ext_token": p.ext_token,
                "ext_pubkey": p.ext_pubkey_b64,
                "hermes_pubkey": p.hermes_pubkey_b64,
                "paired_at": p.paired_at,
                # Any WebAuthn file not explicitly bound to this new token is
                # from an older pairing generation and must be ignored.
                "reject_unbound_webauthn": True,
            }
        )
        _write_private(_state_path(), json.dumps(data).encode("utf-8"))
        # Normal lifecycle cleanup. The state marker above remains the
        # authoritative revocation if unlink fails (permissions/race).
        with _suppress_oserror():
            _webauthn_path().unlink()


# --- v2 key ring (SPEC-v2 §1.3): per-channel Slack keys + extension-chat key ---


def load_channel_keys() -> dict[str, bytes]:
    """channelId → raw K_chan for every stored Slack channel key."""
    data = _read_json(_state_path()) or {}
    out: dict[str, bytes] = {}
    for cid, kb in (data.get("channel_keys") or {}).items():
        try:
            out[cid] = b64u_decode(kb)
        except Exception:
            continue
    return out


def save_channel_key(channel_id: str, raw_key: bytes) -> None:
    with _state_lock():
        data = _read_json(_state_path()) or {}
        ck = dict(data.get("channel_keys") or {})
        ck[channel_id] = b64u_encode(raw_key)
        data["channel_keys"] = ck
        _write_private(_state_path(), json.dumps(data).encode("utf-8"))


def _is_replay_identity(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _replay_timestamp(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _require_active_replay_state(data: dict[str, Any]) -> None:
    aes_key_encoded = data.get("aes_key")
    try:
        active_key_valid = (
            isinstance(aes_key_encoded, str)
            and len(b64u_decode(aes_key_encoded)) == 32
            and b64u_encode(b64u_decode(aes_key_encoded)) == aes_key_encoded
        )
    except Exception:
        active_key_valid = False
    if not isinstance(data.get("ext_token"), str) or not data.get("ext_token") or not active_key_valid:
        raise RuntimeError("active pairing required for E2E replay protection")


def _retained_replay_entries(
    raw_entries: Any,
    *,
    accepted_at: float,
) -> tuple[list[dict[str, Any]], set[str]]:
    if raw_entries is None:
        return [], set()
    if not isinstance(raw_entries, list):
        raise RuntimeError("invalid E2E replay state")

    cutoff = accepted_at - _E2E_REPLAY_TTL_SECONDS
    kept: list[dict[str, Any]] = []
    known: set[str] = set()
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise RuntimeError("invalid E2E replay entry")
        identity = raw.get("id")
        timestamp = _replay_timestamp(raw.get("accepted_at"))
        if not _is_replay_identity(identity) or timestamp is None:
            raise RuntimeError("invalid E2E replay entry")
        # Future timestamps are retained: a backwards clock jump must not
        # erase replay evidence.
        if timestamp >= cutoff or timestamp > accepted_at:
            kept.append({"id": identity, "accepted_at": timestamp})
            known.add(identity)
    return kept, known


def claim_e2e_replay_identities(
    identities: tuple[str, ...],
    *,
    now: float | None = None,
) -> bool:
    """Atomically persist authenticated E2E-v3 replay identities.

    Returns ``False`` if any identity was already accepted, otherwise records
    all of them and returns ``True``. The bounded 30-day cache lives in the
    private pairing state so a gateway restart cannot make captured commands
    fresh again. Callers provide only domain-separated SHA-256 hex digests;
    raw message IDs and nonces are never persisted.
    """
    if not identities or any(not _is_replay_identity(identity) for identity in identities):
        raise ValueError("invalid E2E replay identity")
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate E2E replay identity")

    accepted_at = time.time() if now is None else now
    with _state_lock():
        data = _read_json(_state_path())
        _require_active_replay_state(data)
        kept, known = _retained_replay_entries(
            data.get(_E2E_REPLAY_FIELD),
            accepted_at=accepted_at,
        )

        if any(identity in known for identity in identities):
            return False
        kept.extend({"id": identity, "accepted_at": accepted_at} for identity in identities)
        data[_E2E_REPLAY_FIELD] = kept[-_E2E_REPLAY_MAX_IDENTITIES:]
        _write_private(_state_path(), json.dumps(data, separators=(",", ":")).encode("utf-8"))
        return True


# NOTE: there is deliberately no load/save_extchat_key here. K_extchat is always
# DERIVED fresh from the pairing master key (``api._extchat_key`` →
# ``hkdf_subkey``); a persisted copy was written and read by nobody and would
# only invite a derive-vs-stored mismatch after a re-pair.


def clear_pairing() -> None:
    with _state_lock():
        for name in ("state.json", "webauthn.json"):
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
# pair_init handler (gateway side)
# --------------------------------------------------------------------------- #


def handle_pair_init(code: str, ext_pubkey_b64: str, challenge_b64: str) -> dict[str, Any]:
    """Validate the code, derive the shared key, persist the pairing, and return
    the ``pair_complete`` payload. Raises :class:`PairError` on rejection.

    The outcome is recorded back onto the consumed pending entry (see
    :func:`_mark_pair_result`) so the polling CLI reports rejection instead of
    a false "Paired" when the handshake dies after the code is claimed."""
    code = normalize_code(code)
    _consume_code(code)  # raises on invalid/expired/used — nothing to record

    try:
        try:
            challenge = b64u_decode(challenge_b64)
        except Exception as exc:
            raise PairError("invalid_challenge") from exc
        if len(challenge) < 16:
            raise PairError("invalid_challenge")

        hermes_priv = X25519PrivateKey.generate()
        try:
            aes_key = derive_shared_key(hermes_priv, ext_pubkey_b64, code)
        except Exception as exc:
            raise PairError("invalid_pubkey") from exc

        hermes_pub_b64 = b64u_encode(x25519_public_raw(hermes_priv))
        ext_token = b64u_encode(secrets.token_bytes(32))

        # Everything that can fail (attestation signing included) runs BEFORE
        # _save_pairing: a failure after the save would have replaced a
        # previously-working pairing's key/token with a half-completed one.
        payload = {
            "hermes_pubkey": hermes_pub_b64,
            "ext_token": ext_token,
            "attestation": {
                "signed_challenge": _sign_attestation(challenge),
                "se_pubkey": attest_pubkey_spki_b64(),
                "se_available": se_available(),
            },
        }

        _save_pairing(
            Pairing(
                aes_key=aes_key,
                ext_token=ext_token,
                ext_pubkey_b64=ext_pubkey_b64,
                hermes_pubkey_b64=hermes_pub_b64,
                paired_at=time.time(),
            )
        )
    except PairError as exc:
        # Outcome marking is best-effort UX metadata — never let its I/O
        # failure mask the PairError the extension's pair_fail frame needs.
        with contextlib.suppress(OSError):
            _mark_pair_result(code, "failed", exc.reason)
        raise
    except Exception:
        with contextlib.suppress(OSError):
            _mark_pair_result(code, "failed", "internal_error")
        raise

    with contextlib.suppress(OSError):
        _mark_pair_result(code, "paired")
    return payload
