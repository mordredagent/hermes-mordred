"""Signature-based trust between Hermes and browser extensions (auth v2).

There are no pairing codes. A browser is trusted once the owner approves it at
the Mac that holds the Mordred vault:

- ``V``, the vault approval key: a Secure Enclave P-256 signing key whose every
  use needs Touch ID or the Mac login password. It signs *endorsements* and
  nothing else.
- ``H``, the Hermes identity key: an Enclave signing key that needs no prompt.
  It signs every handshake and is itself endorsed by ``V`` (``hermes-id``).
- ``D``, a browser's device key: a non-extractable WebCrypto key. A browser is
  trusted while a ``device-add`` endorsement by ``V`` names its key.

The roots (``V`` and ``H``) and the revocation list live in a vault file
(:data:`VAULT_FILE`). The vault manifest is MACed under the vault master and
pinned by the Keychain anchor, so a swapped ``V`` or a rolled-back revocation
list is detected.

The endorsements themselves live outside the vault, in
``<hermes home>/extension/`` (:data:`LEDGER_FILE`). Approving a browser then
asks for Touch ID once, for ``V``'s signature, and not a second time to unwrap
the vault for the write. Nothing in that file needs the vault's protection:

- every endorsement is re-verified against ``V`` on load, so an entry that ``V``
  did not sign is ignored;
- removing a browser writes the endorsement's digest into the vault's
  revocation list, so copying an old endorsement back into the file does not
  bring that browser back;
- deleting the file only means the browsers must be approved again.

Removing a device needs no ``V`` signature. Endorsements stored in the vault
by earlier versions are still honoured.

An endorsement is ``{"body": <JSON text>, "sig": <base64url r||s>}``: the
signature covers :data:`ENDORSE_CONTEXT` followed by the body's UTF-8 bytes,
so a verifier never has to re-serialise JSON.

Test root: with ``MORDRED_EXT_TEST_ROOT=1`` and a ``HERMES_HOME`` other than
``~/.hermes``, ``V`` and ``H`` are software keys sealed in the vault and an
approval needs no touch, so headless browsers can be tested end to end. A test
root is refused under the default home, and a stored test root is refused
whenever the variable is unset.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_log = logging.getLogger(__name__)

VAULT_FILE: Final = "extension-trust.json"
LEDGER_FILE: Final = "devices.json"
TEST_ROOT_ENV: Final = "MORDRED_EXT_TEST_ROOT"
ENDORSE_CONTEXT: Final = b"mordred-ext-endorse-v1\n"
CLIENT_CONTEXT: Final = b"mordred-ext-auth-v2 client\n"
SERVER_CONTEXT: Final = b"mordred-ext-auth-v2 server\n"
SAS_CONTEXT: Final = b"mordred-ext-sas-v1\n"
SESSION_INFO: Final = b"mordred-session-v2"
AUTH_VERSION: Final = 2
_SAS_ALPHABET: Final = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CACHE_SECONDS: Final = 2.0
_MAX_LABEL: Final = 64
_STORE_VERSION: Final = 1


class TrustError(Exception):
    """A refusal with a stable wire ``reason``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Encoding and signatures
# --------------------------------------------------------------------------- #


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: Any) -> bytes:
    if not isinstance(text, str) or not text or len(text) > 4096:
        raise TrustError("bad_encoding")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise TrustError("bad_encoding") from exc


def body_text(fields: dict[str, Any]) -> str:
    """The JSON text a signature covers (sorted keys, no spaces, UTF-8)."""
    return json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def spki_from_point(x963: bytes) -> bytes:
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), x963)
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _public_key(spki: bytes) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_der_public_key(spki)
    except ValueError as exc:
        raise TrustError("bad_key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise TrustError("bad_key")
    return key


def verify(spki: bytes, message: bytes, signature: bytes) -> bool:
    """ECDSA P-256 / SHA-256 over ``message``; ``signature`` is raw r || s."""
    if len(signature) != 64:
        return False
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        _public_key(spki).verify(der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, TrustError):
        return False
    return True


def device_id_of(device_spki: bytes) -> str:
    return b64u(hashlib.sha256(device_spki).digest())[:22]


def fingerprint(spki: bytes) -> str:
    """A short, human-comparable fingerprint of a public key."""
    digest = hashlib.sha256(spki).hexdigest()[:16].upper()
    return " ".join(digest[i : i + 4] for i in range(0, 16, 4))


def sas(v_spki: bytes, hermes_spki: bytes, device_spki: bytes, nonce_s: bytes, nonce_c: bytes) -> str:
    """Six characters both sides show at first contact (30 bits)."""
    digest = hashlib.sha256(SAS_CONTEXT + v_spki + hermes_spki + device_spki + nonce_s + nonce_c).digest()
    bits = int.from_bytes(digest[:4], "big") >> 2
    chars = "".join(_SAS_ALPHABET[(bits >> (5 * (5 - i))) & 31] for i in range(6))
    return f"{chars[:3]}-{chars[3:]}"


def session_key(eph_private: x25519.X25519PrivateKey, peer_public: bytes, hello_body: str, reply_body: str) -> bytes:
    """K_extchat for one socket: HKDF over X25519, salted with both signed bodies."""
    try:
        shared = eph_private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:
        raise TrustError("bad_key") from exc
    salt = hashlib.sha256(hello_body.encode() + b"\n" + reply_body.encode()).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=SESSION_INFO).derive(shared)


# --------------------------------------------------------------------------- #
# Signers
# --------------------------------------------------------------------------- #


class Signer(Protocol):
    @property
    def spki(self) -> bytes: ...

    def sign(self, messages: Sequence[bytes], reason: str) -> list[bytes]: ...


@dataclass(frozen=True)
class _EnclaveSigner:
    tag: bytes
    spki: bytes

    def sign(self, messages: Sequence[bytes], reason: str) -> list[bytes]:
        from ..keyvault._seckey_errors import _OpsError

        ops = _helper()
        try:
            signatures: list[bytes] = ops.sign(self.tag, list(messages), reason)
            return signatures
        except _OpsError as exc:
            # LAError.userCancel / systemCancel / appCancel, or the helper's own timeout.
            _log.info("extension trust: approval not given (%s %s)", exc.domain, exc.status)
            raise TrustError("approval_denied") from exc


@dataclass(frozen=True)
class _SoftwareSigner:
    private: ec.EllipticCurvePrivateKey = field(repr=False)
    spki: bytes

    def sign(self, messages: Sequence[bytes], reason: str) -> list[bytes]:
        out = []
        for message in messages:
            r, s = utils.decode_dss_signature(self.private.sign(message, ec.ECDSA(hashes.SHA256())))
            out.append(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return out


def _software_signer(pkcs8: bytes) -> _SoftwareSigner:
    key = serialization.load_der_private_key(pkcs8, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TrustError("bad_key")
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return _SoftwareSigner(key, spki)


def _new_software_key() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _helper() -> Any:
    from ..keyvault import _seckey_helper

    binary = _seckey_helper.find_sekey_sign_helper()
    if binary is None:
        raise TrustError("enclave_unavailable")
    return _seckey_helper._HelperSecKeyOps(binary)


def test_root_allowed() -> bool:
    if os.environ.get(TEST_ROOT_ENV) != "1":
        return False
    from .._core._home import hermes_home

    return hermes_home().resolve() != (Path.home() / ".hermes").resolve()


# --------------------------------------------------------------------------- #
# Endorsements and the trust state
# --------------------------------------------------------------------------- #


def endorsement_body(action: str, vault_id: str, hermes_spki: bytes, subject: dict[str, Any]) -> str:
    return body_text(
        {
            "v": 1,
            "action": action,
            "vault_id": vault_id,
            "hermes_spki": b64u(hermes_spki),
            "subject": subject,
            "nonce": b64u(secrets.token_bytes(16)),
            "issued_at": int(time.time()),
        }
    )


def check_endorsement(
    endorsement: Any, v_spki: bytes, *, action: str, vault_id: str, hermes_spki: bytes
) -> dict[str, Any]:
    """The verified body of an endorsement; :class:`TrustError` otherwise."""
    if not isinstance(endorsement, dict) or not isinstance(endorsement.get("body"), str):
        raise TrustError("bad_endorsement")
    body = endorsement["body"]
    if not verify(v_spki, ENDORSE_CONTEXT + body.encode(), unb64u(endorsement.get("sig"))):
        raise TrustError("bad_endorsement")
    fields = json.loads(body)
    if (
        not isinstance(fields, dict)
        or fields.get("v") != 1
        or fields.get("action") != action
        or fields.get("vault_id") != vault_id
        or fields.get("hermes_spki") != b64u(hermes_spki)
        or not isinstance(fields.get("subject"), dict)
    ):
        raise TrustError("bad_endorsement")
    return fields


@dataclass(frozen=True)
class Device:
    device_id: str
    spki: bytes
    label: str
    added_at: int
    endorsement: dict[str, str]

    @property
    def generation(self) -> bytes:
        """Changes whenever this device's endorsement does; gone when it is removed.

        Taken over the signed body, not the signature: an ECDSA signature can be
        rewritten (``s`` to ``n - s``) into a second valid one, which would slip
        past a revocation list of signature hashes.
        """
        return hashlib.sha256(self.endorsement["body"].encode()).digest()

    @property
    def digest(self) -> str:
        """This endorsement's name in the vault's revocation list."""
        return b64u(self.generation)


@dataclass(frozen=True)
class Trust:
    kind: str  # "enclave" | "test"
    vault_id: str
    v: Signer = field(repr=False)
    h: Signer = field(repr=False)
    hermes_id: dict[str, str] | None
    devices: dict[str, Device]
    #: Digests (:attr:`Device.digest`) of endorsements that were removed.
    revoked: frozenset[str] = frozenset()

    @property
    def v_spki(self) -> bytes:
        return self.v.spki

    @property
    def hermes_spki(self) -> bytes:
        return self.h.spki


def _vault_id(key_id: str) -> str:
    return b64u(hashlib.sha256(b"mordred-vault-id\n" + key_id.encode()).digest())[:22]


def _signers(doc: dict[str, Any]) -> tuple[str, Signer, Signer]:
    kind = str(doc.get("kind"))
    if kind == "test":
        if not test_root_allowed():
            raise TrustError("test_root_refused")
        return kind, _software_signer(unb64u(doc.get("test_v"))), _software_signer(unb64u(doc.get("test_h")))
    if kind == "enclave":
        v = _EnclaveSigner(unb64u(doc.get("v_tag")), unb64u(doc.get("v_spki")))
        return kind, v, _EnclaveSigner(unb64u(doc.get("h_tag")), unb64u(doc.get("h_spki")))
    raise TrustError("trust_unreadable")


def _checked_hermes_id(entry: Any, v: Signer, h: Signer, vault_id: str) -> dict[str, str] | None:
    if entry is None:
        return None
    try:
        fields = check_endorsement(entry, v.spki, action="hermes-id", vault_id=vault_id, hermes_spki=h.spki)
    except TrustError:
        fields = None
    if fields is None or fields["subject"].get("hermes_spki") != b64u(h.spki):
        _log.warning("extension trust: hermes-id endorsement does not verify; ignored")
        return None
    return dict(entry)


def _checked_device(device_id: str, entry: Any, v: Signer, h: Signer, vault_id: str) -> Device | None:
    try:
        fields = check_endorsement(entry, v.spki, action="device-add", vault_id=vault_id, hermes_spki=h.spki)
        spki = unb64u(fields["subject"].get("device_spki"))
        if device_id_of(spki) != device_id:
            raise TrustError("bad_endorsement")
    except (TrustError, ValueError):
        _log.warning("extension trust: a device endorsement does not verify; ignored")
        return None
    label = str(fields["subject"].get("label", ""))[:_MAX_LABEL]
    return Device(device_id, spki, label, int(fields["issued_at"]), dict(entry))


def _parse(doc: dict[str, Any], vault_id: str) -> Trust:
    if doc.get("v") != _STORE_VERSION:
        raise TrustError("trust_unreadable")
    kind, v, h = _signers(doc)
    revoked = doc.get("revoked", [])
    if not isinstance(revoked, list) or not all(isinstance(r, str) for r in revoked):
        raise TrustError("trust_unreadable")
    hermes_id = _checked_hermes_id(doc.get("hermes_id"), v, h, vault_id)
    devices: dict[str, Device] = {}
    if hermes_id is not None:
        for device_id, entry in (doc.get("devices") or {}).items():
            if (device := _checked_device(device_id, entry, v, h, vault_id)) is not None:
                devices[device_id] = device
    return Trust(kind, vault_id, v, h, hermes_id, devices, frozenset(revoked))


def _serialise(trust: Trust, keys: dict[str, str]) -> bytes:
    doc: dict[str, Any] = {"v": _STORE_VERSION, "kind": trust.kind, **keys}
    if trust.hermes_id is not None:
        doc["hermes_id"] = trust.hermes_id
    doc["devices"] = {d.device_id: d.endorsement for d in trust.devices.values()}
    if trust.revoked:
        doc["revoked"] = sorted(trust.revoked)
    return json.dumps(doc, sort_keys=True).encode()


def _merge(base: Trust, ledger: dict[str, Any]) -> Trust:
    """``base`` (read from the vault) with the ledger's endorsements, minus revocations."""
    hermes_id = base.hermes_id or _checked_hermes_id(ledger.get("hermes_id"), base.v, base.h, base.vault_id)
    devices: dict[str, Device] = {}
    entries = ledger.get("devices")
    found = list(base.devices.values())
    if hermes_id is not None and isinstance(entries, dict):
        for device_id, entry in entries.items():
            if (device := _checked_device(device_id, entry, base.v, base.h, base.vault_id)) is not None:
                found.append(device)
    for device in found:
        if device.digest in base.revoked:
            continue
        held = devices.get(device.device_id)
        if held is None or device.added_at > held.added_at:
            devices[device.device_id] = device
    return replace(base, hermes_id=hermes_id, devices=devices)


def _new_roots(vault_id: str) -> tuple[Trust, dict[str, str]]:
    """New ``V`` and ``H`` keys, and the fields that store them (no prompt)."""
    if test_root_allowed():
        v_der, h_der = _new_software_key(), _new_software_key()
        v, h = _software_signer(v_der), _software_signer(h_der)
        return Trust("test", vault_id, v, h, None, {}), {"test_v": b64u(v_der), "test_h": b64u(h_der)}
    ops = _helper()
    v_tag, h_tag = secrets.token_bytes(16), secrets.token_bytes(16)
    v_spki = spki_from_point(ops.create_signing_key(v_tag, unattended=False))
    h_spki = spki_from_point(ops.create_signing_key(h_tag, unattended=True))
    return Trust("enclave", vault_id, _EnclaveSigner(v_tag, v_spki), _EnclaveSigner(h_tag, h_spki), None, {}), {
        "v_tag": b64u(v_tag),
        "v_spki": b64u(v_spki),
        "h_tag": b64u(h_tag),
        "h_spki": b64u(h_spki),
    }


# --------------------------------------------------------------------------- #
# The vault-backed store
# --------------------------------------------------------------------------- #


class _Vault(Protocol):
    @property
    def generation(self) -> int: ...

    def list_files(self) -> list[str]: ...
    def read_file(self, name: str) -> bytes: ...
    def enroll_file(self, name: str, plaintext: bytes) -> None: ...
    def close(self) -> None: ...


Opener = Callable[[], tuple[_Vault, str]]
Probe = Callable[[], int]


def _open_default_vault() -> tuple[_Vault, str]:
    """The Mordred vault and its key id; :class:`TrustError` when unavailable."""
    import sys

    if sys.platform != "darwin" and not test_root_allowed():
        raise TrustError("trust_unavailable")
    from ..keyvault import vault
    from ..keyvault._identity import default_vault_root, resolve_backend_store, vault_identity

    root = default_vault_root()
    if not vault.artifacts_present(root):
        raise TrustError("vault_not_initialized")
    key_id = vault_identity(root)
    try:
        backend, store = resolve_backend_store(None, None)
        return vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=key_id), key_id
    except Exception as exc:
        raise TrustError("vault_unavailable") from exc


def _default_vault_generation() -> int:
    """The vault's committed generation, read from its device anchor.

    A Keychain read: unlike opening the vault, it never unwraps the master key,
    so it never asks for Touch ID.
    """
    from ..keyvault import anchor
    from ..keyvault._identity import default_vault_root, resolve_backend_store, vault_identity

    root = default_vault_root()
    try:
        _backend, anchor_store = resolve_backend_store(None, None)
        return anchor.read_anchor(anchor_store, vault_identity(root)).generation
    except Exception as exc:
        raise TrustError("vault_unavailable") from exc


def _default_ledger() -> Path:
    from . import pairing

    return pairing._ext_dir() / LEDGER_FILE


@dataclass(frozen=True)
class _Snapshot:
    generation: int
    trust: Trust | None
    checked_at: float


class TrustStore:
    """The trust state: roots and revocations in the vault, endorsements beside it.

    Opening the vault unwraps its master key, which can ask for Touch ID on
    every open. So the vault part is read once and kept; a later read only
    compares the vault's committed generation (a Keychain read, no prompt) and
    reopens the vault only when another writer committed since — for example
    ``extension devices --remove`` in another process. The ledger file is read
    again whenever it changes on disk.

    Approving a browser writes only the ledger, so it never opens the vault.
    """

    def __init__(
        self,
        opener: Opener = _open_default_vault,
        clock: Callable[[], float] = time.monotonic,
        probe: Probe = _default_vault_generation,
        ledger: Callable[[], Path] = _default_ledger,
    ) -> None:
        self._opener = opener
        self._probe = probe
        self._clock = clock
        self._ledger = ledger
        self._lock = threading.RLock()
        # Approvals are one at a time: a second browser waits for the first sheet.
        self._approval = threading.Lock()
        self._cached: _Snapshot | None = None
        # (vault state, ledger file stamp, the two merged)
        self._merged: tuple[Trust, Any, Trust] | None = None

    def prime(self, opened: _Vault, key_id: str) -> None:
        """Read the state from a vault another reader just opened, saving an unlock.

        ``extension serve`` opens the vault at start for its environment; reading
        the trust state there means the first browser to connect asks for
        nothing. A vault that has no roots yet gets them here, so the first
        approval does not have to open the vault to create them.
        """
        import sys

        with self._lock:
            current = self._read(opened, key_id)
            if current is None and (sys.platform == "darwin" or test_root_allowed()):
                try:
                    current, keys = _new_roots(_vault_id(key_id))
                    opened.enroll_file(VAULT_FILE, _serialise(current, keys))
                except Exception as exc:
                    # The first browser to connect creates them instead.
                    _log.warning("extension trust: approval keys not created at start (%s)", type(exc).__name__)
                    current = None
            self._cached = _Snapshot(opened.generation, current, self._clock())

    def invalidate(self) -> None:
        with self._lock:
            self._cached = None

    def load(self, *, fresh: bool = False) -> Trust | None:
        """The trust state, ``None`` before the first browser was ever seen."""
        with self._lock:
            base = self._load_vault(fresh)
            return None if base is None else self._with_ledger(base)

    def _load_vault(self, fresh: bool) -> Trust | None:
        now = self._clock()
        cached = self._cached
        if (
            not fresh
            and cached is not None
            and (now - cached.checked_at < _CACHE_SECONDS or self._probe() == cached.generation)
        ):
            self._cached = replace(cached, checked_at=now)
            return cached.trust
        opened, key_id = self._opener()
        try:
            trust = self._read(opened, key_id)
            self._cached = _Snapshot(opened.generation, trust, now)
        finally:
            opened.close()
        return trust

    @staticmethod
    def _read(opened: _Vault, key_id: str) -> Trust | None:
        if VAULT_FILE not in opened.list_files():
            return None
        try:
            doc = json.loads(opened.read_file(VAULT_FILE))
        except ValueError as exc:
            raise TrustError("trust_unreadable") from exc
        if not isinstance(doc, dict):
            raise TrustError("trust_unreadable")
        return _parse(doc, _vault_id(key_id))

    def _with_ledger(self, base: Trust) -> Trust:
        stamp = self._ledger_stamp()
        merged = self._merged
        if merged is not None and merged[0] is base and stamp is not None and merged[1] == stamp:
            return merged[2]
        result = _merge(base, self._read_ledger())
        self._merged = (base, stamp, result)
        return result

    def _ledger_stamp(self) -> Any:
        """Identifies the ledger file's current contents; ``None`` when unknown."""
        try:
            metadata = os.stat(self._ledger())
        except FileNotFoundError:
            return "absent"
        except OSError:
            return None
        return (metadata.st_ino, metadata.st_mtime_ns, metadata.st_size)

    def _read_ledger(self) -> dict[str, Any]:
        from . import pairing

        try:
            return pairing._read_json(self._ledger())
        except (OSError, RuntimeError) as exc:
            # Fails closed: its browsers are simply not trusted until approved again.
            _log.warning("extension trust: %s is unreadable (%s); ignored", LEDGER_FILE, type(exc).__name__)
            return {}

    def _edit_ledger(self, edit: Callable[[dict[str, Any]], None]) -> None:
        from . import pairing

        with self._lock, pairing._state_lock():
            current = self._read_ledger()
            devices = current.get("devices")
            doc: dict[str, Any] = {
                "v": _STORE_VERSION,
                "hermes_id": current.get("hermes_id"),
                "devices": dict(devices) if isinstance(devices, dict) else {},
            }
            edit(doc)
            pairing._write_private(self._ledger(), json.dumps(doc, sort_keys=True).encode())

    def _update(self, mutate: Callable[[Trust | None, str, dict[str, str]], tuple[Trust, dict[str, str]]]) -> Trust:
        with self._lock:
            self._cached = None
            opened, key_id = self._opener()
            try:
                current = self._read(opened, key_id)
                keys = self._keys(opened) if current is not None else {}
                updated, keys = mutate(current, _vault_id(key_id), keys)
                opened.enroll_file(VAULT_FILE, _serialise(updated, keys))
                self._cached = _Snapshot(opened.generation, updated, self._clock())
            finally:
                opened.close()
            return updated

    @staticmethod
    def _keys(opened: _Vault) -> dict[str, str]:
        doc = json.loads(opened.read_file(VAULT_FILE))
        return {k: doc[k] for k in ("v_tag", "v_spki", "h_tag", "h_spki", "test_v", "test_h") if k in doc}

    def ensure_root(self) -> Trust:
        """The trust state, creating ``V`` and ``H`` on first use (no prompt)."""
        trust = self.load()
        if trust is not None:
            return trust

        def create(current: Trust | None, vault_id: str, keys: dict[str, str]) -> tuple[Trust, dict[str, str]]:
            if current is not None:
                return current, keys
            return _new_roots(vault_id)

        with self._lock:
            return self._with_ledger(self._update(create))

    def approve(self, device_spki: bytes, label: str, origin: str, code: str) -> Trust:
        """Ask ``V`` to endorse a browser (Touch ID or the login password), then store it.

        The first approval also endorses ``H``, under the same authorization.
        The endorsements go to the ledger file, so this is the only prompt.
        """
        if not self._approval.acquire(blocking=False):
            raise TrustError("approval_busy")
        try:
            trust = self.ensure_root()
            label = clean_label(label)
            device_body = endorsement_body(
                "device-add",
                trust.vault_id,
                trust.hermes_spki,
                {"device_spki": b64u(device_spki), "label": label, "origin": origin, "sas": code},
            )
            bodies = [device_body]
            if trust.hermes_id is None:
                bodies.append(
                    endorsement_body(
                        "hermes-id", trust.vault_id, trust.hermes_spki, {"hermes_spki": b64u(trust.hermes_spki)}
                    )
                )
            reason = f"allow the browser “{label}” to connect to Mordred. Code {code}"
            if trust.kind == "test" and not test_root_allowed():
                raise TrustError("test_root_refused")
            signatures = trust.v.sign([ENDORSE_CONTEXT + b.encode() for b in bodies], reason)
            for body, signature in zip(bodies, signatures, strict=True):
                # Never store what the pinned V did not sign.
                if not verify(trust.v_spki, ENDORSE_CONTEXT + body.encode(), signature):
                    raise TrustError("approval_denied")
            endorsements = [{"body": b, "sig": b64u(s)} for b, s in zip(bodies, signatures, strict=True)]

            def add(doc: dict[str, Any]) -> None:
                doc["devices"][device_id_of(device_spki)] = endorsements[0]
                if len(endorsements) > 1:
                    doc["hermes_id"] = endorsements[1]

            # A root that changed meanwhile simply does not verify these on load.
            self._edit_ledger(add)
            if (state := self.load()) is None:
                raise TrustError("trust_changed")
            return state
        finally:
            self._approval.release()

    def remove(self, device_id: str) -> bool:
        """Forget a browser. Needs no approval: removing trust is always allowed.

        The endorsement's digest goes into the vault, so copying it back into
        the ledger file does not bring the browser back.
        """
        removed = False

        def revoke(current: Trust | None, vault_id: str, keys: dict[str, str]) -> tuple[Trust, dict[str, str]]:
            nonlocal removed
            if current is None:
                raise TrustError("unknown_device")
            known = [current.devices.get(device_id), self._with_ledger(current).devices.get(device_id)]
            digests = {d.digest for d in known if d is not None}
            removed = bool(digests)
            devices = {k: d for k, d in current.devices.items() if k != device_id}
            return replace(current, devices=devices, revoked=current.revoked | digests), keys

        self._update(revoke)
        self._edit_ledger(lambda doc: doc["devices"].pop(device_id, None))
        return removed


def clean_label(label: Any) -> str:
    text = "".join(ch for ch in str(label or "") if ch.isprintable()).strip()
    return text[:_MAX_LABEL] or "Browser"


_default: TrustStore | None = None
_default_lock = threading.Lock()


def store() -> TrustStore:
    """The process-wide store over the default vault."""
    global _default
    with _default_lock:
        if _default is None:
            _default = TrustStore()
        return _default


def set_store(replacement: TrustStore | None) -> None:
    """Swap the process-wide store (tests)."""
    global _default
    with _default_lock:
        _default = replacement
