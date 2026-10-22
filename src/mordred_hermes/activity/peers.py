"""Activity peer credentials: pair codes, peer tokens, revocation, fingerprints.

An *activity peer* (today: the operator collector) submits activity batches to
the extension API with its own credential, scoped to activity submission and
revocable independently of the paired browser extension. The handshake reuses
the extension pairing infrastructure (:mod:`mordred_hermes.extension.pairing`:
private directory, atomic 0600 writes, the cross-process state lock, the
``MORT-XXXXXXXX-XXXXXXXX`` code shape) but keeps its own files, so a code is
purpose-bound:

- ``<home>/extension/activity_pending.json`` — pending activity pair codes,
  keyed by ``sha256(code)``: ``{expires_at, label, outcome, fail_reason, peer_id}``.
  ``pairing.handle_pair_init`` never reads this file and :func:`handle_pair_init`
  here never reads the extension's ``pending.json``.
- ``<home>/extension/activity_peers.json`` — ``{peer_id: {token_sha256, label,
  kind, created_at, revoked_at}}``. Only the SHA-256 of a peer token is stored;
  comparison uses :func:`secrets.compare_digest`.

Nothing here logs a code, a token, or a digest.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import secrets
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..extension import pairing
from ..extension._windows_storage import ExtensionStorageError
from ..extension.crypto import b64u_encode
from .contracts import PeerPrincipal as PeerPrincipal

_PENDING_FILE = "activity_pending.json"
_PEERS_FILE = "activity_peers.json"
CODE_TTL_SECONDS = 10 * 60
# Settled or expired pending entries are kept this long so the polling CLI can
# read the outcome, then pruned on the next code generation.
_PENDING_RETENTION_SECONDS = CODE_TTL_SECONDS
_MAX_LABEL_CHARS = 64
_PEER_ID_PREFIX = "operator:"
_DEFAULT_LABEL = "operator"


EXTENSION_PRINCIPAL = PeerPrincipal(peer_id="extension", kind="browser")


class PeerPairError(Exception):
    """``activity_pair_fail``. ``reason``: invalid_code | expired_code | used_code | storage_refused."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# File helpers (all delegated to the extension pairing store)
# --------------------------------------------------------------------------- #


def _pending_path() -> Path:
    return pairing._ext_dir() / _PENDING_FILE


def _peers_path() -> Path:
    return pairing._ext_dir() / _PEERS_FILE


def _write(path: Path, data: dict[str, Any]) -> None:
    pairing._write_private(path, json.dumps(data, sort_keys=True).encode("utf-8"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _code_digest(code: str) -> str:
    return _sha256(pairing.normalize_code(code))


def _clean_label(label: object) -> str:
    if not isinstance(label, str):
        return _DEFAULT_LABEL
    text = "".join(ch for ch in label.strip() if ch.isprintable())[:_MAX_LABEL_CHARS]
    return text or _DEFAULT_LABEL


@contextlib.contextmanager
def _storage_guard() -> Iterator[None]:
    """Map every storage failure to the content-free ``storage_refused`` reason."""
    try:
        yield
    except PeerPairError:
        raise
    except (OSError, RuntimeError, ExtensionStorageError) as exc:
        raise PeerPairError("storage_refused") from exc


# --------------------------------------------------------------------------- #
# Pair codes
# --------------------------------------------------------------------------- #


def generate_peer_code(label: str = _DEFAULT_LABEL) -> tuple[str, float]:
    """Create a single-use activity pair code; return ``(code, expires_at)``."""
    raw = "".join(secrets.choice(pairing._CODE_ALPHABET) for _ in range(16))
    code = pairing._format_code(raw)
    now = time.time()
    expires_at = now + CODE_TTL_SECONDS
    path = _pending_path()
    with pairing._state_lock():
        pending = pairing._read_json(path)
        pending = {
            k: v
            for k, v in pending.items()
            if isinstance(v, dict) and float(v.get("expires_at", 0)) + _PENDING_RETENTION_SECONDS > now
        }
        pending[_code_digest(code)] = {
            "expires_at": expires_at,
            "label": _clean_label(label),
            "outcome": None,
        }
        _write(path, pending)
    return code, expires_at


def _claim_code(pending: dict[str, Any], digest: str, now: float) -> dict[str, Any]:
    entry = pending.get(digest)
    if not isinstance(entry, dict):
        raise PeerPairError("invalid_code")
    if entry.get("outcome") is not None:
        raise PeerPairError("used_code")
    if float(entry.get("expires_at", 0)) < now:
        entry["outcome"] = "failed"
        entry["fail_reason"] = "expired_code"
        raise PeerPairError("expired_code")
    return entry


def handle_pair_init(code: object, label: object = None) -> dict[str, str]:
    """Consume an activity pair code and mint a peer credential.

    Returns ``{"peer_id", "peer_token"}``; raises :class:`PeerPairError`. The
    wire ``label`` is a peer-supplied hint and is ignored: the label recorded
    for the peer is the one the operator gave ``pair-operator``.
    """
    del label  # peer-supplied labels are never trusted (design: ingestion)
    if not isinstance(code, str) or not code:
        raise PeerPairError("invalid_code")
    digest = _code_digest(code)
    pending_path = _pending_path()
    with _storage_guard(), pairing._state_lock():
        pending = pairing._read_json(pending_path)
        now = time.time()
        try:
            entry = _claim_code(pending, digest, now)
        except PeerPairError as exc:
            if exc.reason == "expired_code":
                _write(pending_path, pending)
            raise
        # Burn the code before minting: a failure below never leaves it reusable.
        entry["outcome"] = "claimed"
        _write(pending_path, pending)
        peer_id = f"{_PEER_ID_PREFIX}{secrets.token_hex(6)}"
        peer_token = b64u_encode(secrets.token_bytes(32))
        try:
            peers_path = _peers_path()
            peers = pairing._read_json(peers_path)
            peers[peer_id] = {
                "token_sha256": _sha256(peer_token),
                "label": entry.get("label") or _DEFAULT_LABEL,
                "kind": "operator",
                "created_at": now,
                "revoked_at": None,
            }
            _write(peers_path, peers)
        except (OSError, RuntimeError, ExtensionStorageError):
            entry["outcome"] = "failed"
            entry["fail_reason"] = "storage_refused"
            with contextlib.suppress(OSError, RuntimeError, ExtensionStorageError):
                _write(pending_path, pending)
            raise
        entry["outcome"] = "paired"
        entry["peer_id"] = peer_id
        _write(pending_path, pending)
    return {"peer_id": peer_id, "peer_token": peer_token}


def revoke_peer_code(code: str) -> bool:
    """Burn a pending code that has not been used (CLI cancel/timeout)."""
    path = _pending_path()
    with pairing._state_lock():
        pending = pairing._read_json(path)
        entry = pending.get(_code_digest(code))
        if not isinstance(entry, dict) or entry.get("outcome") is not None:
            return False
        entry["outcome"] = "failed"
        entry["fail_reason"] = "cancelled"
        _write(path, pending)
        return True


def pair_outcome(code: str) -> tuple[str, str | None]:
    """CLI polling: ``(state, reason)`` with state pending | paired | failed | expired."""
    with pairing._state_lock():
        entry = pairing._read_json(_pending_path()).get(_code_digest(code))
    if not isinstance(entry, dict):
        return ("expired", None)
    outcome = entry.get("outcome")
    if outcome == "paired":
        return ("paired", None)
    if outcome == "failed":
        reason = entry.get("fail_reason")
        return ("failed", reason if isinstance(reason, str) else "unknown")
    if outcome is None and float(entry.get("expires_at", 0)) < time.time():
        return ("expired", None)
    return ("pending", None)


# --------------------------------------------------------------------------- #
# Peers
# --------------------------------------------------------------------------- #


def check_token(peer_token: object) -> tuple[PeerPrincipal | None, str | None]:
    """``(principal, None)`` for a live token, else ``(None, invalid_token|peer_revoked)``.

    Unreadable or corrupt peer state fails closed as ``invalid_token``. Every
    stored digest is compared so timing does not reveal the matching position.
    """
    if not isinstance(peer_token, str) or not peer_token:
        return None, "invalid_token"
    try:
        peers = pairing._read_json(_peers_path())
    except (OSError, RuntimeError):
        return None, "invalid_token"
    digest = _sha256(peer_token)
    match: tuple[str, dict[str, Any]] | None = None
    for peer_id, record in peers.items():
        stored = record.get("token_sha256") if isinstance(record, dict) else None
        if isinstance(stored, str) and secrets.compare_digest(stored, digest) and match is None:
            match = (peer_id, record)
    if match is None:
        return None, "invalid_token"
    peer_id, record = match
    if record.get("revoked_at") is not None:
        return None, "peer_revoked"
    kind = str(record.get("kind") or "operator")
    if kind == "hermes":  # Hermes's own capture is an in-process principal, never a paired peer
        return None, "invalid_token"
    return PeerPrincipal(peer_id=peer_id, kind=kind), None


def authenticate(peer_token: object) -> PeerPrincipal | None:
    """The principal for a live peer token, else ``None``."""
    return check_token(peer_token)[0]


def revoke(peer_id: str) -> bool:
    """Revoke a peer. Idempotent: ``False`` when unknown or already revoked."""
    path = _peers_path()
    with pairing._state_lock():
        peers = pairing._read_json(path)
        record = peers.get(peer_id)
        if not isinstance(record, dict) or record.get("revoked_at") is not None:
            return False
        record["revoked_at"] = time.time()
        _write(path, peers)
        return True


def list_peers() -> list[dict[str, Any]]:
    """Peer metadata (never token digests), oldest first."""
    peers = pairing._read_json(_peers_path())
    rows = [
        {
            "peer_id": peer_id,
            "label": record.get("label"),
            "kind": record.get("kind"),
            "created_at": record.get("created_at"),
            "revoked_at": record.get("revoked_at"),
        }
        for peer_id, record in peers.items()
        if isinstance(record, dict)
    ]
    return sorted(rows, key=lambda row: float(row.get("created_at") or 0))


def fingerprint(peer_id: str | None = None) -> bytes | None:
    """Digest for per-frame revalidation of an activity socket.

    Without ``peer_id``: digest of the whole peers file (``None`` when absent).
    With ``peer_id``: digest of that peer's record (``None`` when the peer is
    absent or revoked), so pairing or revoking *another* peer does not drop
    this peer's open session, while revoking or re-pairing this one does.
    """
    peers = pairing._read_json(_peers_path())
    if peer_id is None:
        if not peers:
            return None
        material: Any = peers
    else:
        record = peers.get(peer_id)
        if not isinstance(record, dict) or record.get("revoked_at") is not None:
            return None
        material = {peer_id: record}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).digest()
