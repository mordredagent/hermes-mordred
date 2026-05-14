"""Secure-Enclave-backed DEK wrap/unwrap.

Phase 4 PR3 step-B. The contract is frozen in SPEC.md §Wrap wire format
& algorithm (2026-05-14):

- 127-byte blob: ``MRKW(4)|version(1)|alg_suite(1)|key_id_hash(16)|
  ephemeral_pub(65)|wrapped_dek(40)`` for ``version=1``.
- ``wrap_dek`` is offline — uses the cached Enclave **public** key plus
  a freshly generated software ephemeral private key. No authorization
  prompt; no audit entry on success.
- ``unwrap_dek`` is authorized — calls ``enclave_ecdh`` which on macOS
  routes to ``SecKeyCopyKeyExchangeResult`` and may prompt the user.
  Emits exactly one of ``keyvault.unwrap_authorized`` /
  ``keyvault.unwrap_denied`` per call.
- HKDF ``info`` binds every non-secret blob field to the KEK, so a
  tampered ``ephemeral_pub`` or ``key_id_hash`` produces a different
  KEK and AES-KW unwrap fails the AIV check — integrity protection
  despite AES-KW lacking AAD (codex review HIGH-2).
- AES-KW is RFC 3394: 32-byte DEK → 40-byte output, including the 8-byte
  fixed AIV. There is NO separate IV field (codex review BLOCKER-2).

The Enclave authorization boundary is abstracted by the
:class:`NativeBackend` ``Protocol``. Production code uses a backend
that lazy-loads pyobjc on first call (lands in step-C); tests inject a
software ``FakeBackend`` that uses ``cryptography`` for a real P-256
keypair so the HKDF / AES-KW / wire-format code paths are exercised
with real crypto — codex review MEDIUM-4 (mocks must not hide format
bugs).

Internal Python surface (PR3 step-0 freeze, consumed by PR4 ``api.py``):

- :func:`generate_wrapping_key` — create + persist a new Enclave key.
- :func:`get_wrapping_key_public` — return SEC1 uncompressed public key.
- :func:`delete_wrapping_key` — remove from Keychain (idempotent).
- :func:`wrap_dek` — produce a 127-byte blob (offline, no audit).
- :func:`unwrap_dek` — verify + decrypt a blob (authorized, emits audit).

Exception taxonomy is in :mod:`mordred_hermes.keyvault._exceptions`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._exceptions import (
    WrapAuthCancelled,
    WrapIntegrityError,
    WrapParseError,
)

AuditSink = Callable[[dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Wire-format constants (SPEC.md §Wrap wire format & algorithm L437)
# ---------------------------------------------------------------------------

MAGIC: bytes = b"MRKW"
VERSION: int = 1
ALG_SUITE: int = 1  # (P256_ECDH_RAW, HKDF_SHA256, AES256_KW_RFC3394)
DEK_LEN: int = 32
KEY_ID_HASH_LEN: int = 16
EPHEMERAL_PUB_LEN: int = 65  # SEC1 uncompressed P-256: 1 + 32 + 32
WRAPPED_DEK_LEN: int = 40  # RFC 3394 AES-KW for 32-byte input
HEADER_LEN: int = 127

# Offsets (mirror the byte-layout table in SPEC.md):
_OFFSET_MAGIC = 0
_OFFSET_VERSION = 4
_OFFSET_ALG_SUITE = 5
_OFFSET_KEY_ID_HASH = 6
_OFFSET_EPHEMERAL_PUB = 22
_OFFSET_WRAPPED_DEK = 87


# ---------------------------------------------------------------------------
# Backend Protocol
# ---------------------------------------------------------------------------


class NativeBackendError(Exception):
    """Raised by :class:`NativeBackend` to signal an authorization failure.

    ``code`` is one of the translated strings documented in POLICY.md
    code #20 (``user_cancelled``, ``auth_failed``, ``biometry_lockout``,
    ``passcode_not_set``, ``key_not_found``). The raw ``OSStatus`` from
    pyobjc is **not** stored — it carries biometric-attempt-count state
    that should not cross the audit-log boundary.
    """

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code: str = code


class NativeBackend(Protocol):
    """Narrow Secure-Enclave boundary (codex review MEDIUM-4).

    All four methods are I/O against the Keychain or Enclave. HKDF +
    AES-KW + wire-format parsing live in :mod:`wrap` and are exercised
    with real crypto in the unit tests; only Enclave authorization is
    mocked.
    """

    def generate_enclave_key(self, key_id: str) -> bytes:
        """Create a new Enclave-backed P-256 keypair tagged with
        ``key_id`` and return the SEC1 uncompressed public key. Raises
        :class:`WrapKeyNotFound` if a key with this id already exists
        (the production backend translates ``errSecDuplicateItem``)."""
        ...

    def get_enclave_public_key(self, key_id: str) -> bytes:
        """Return the SEC1 uncompressed public key for ``key_id``.
        Raises :class:`WrapKeyNotFound` if the Keychain has no item."""
        ...

    def delete_enclave_key(self, key_id: str) -> None:
        """Remove the Keychain item for ``key_id``. Idempotent — no-op
        when the item does not exist (mirrors ``errSecItemNotFound``
        being treated as success in production)."""
        ...

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        """Compute raw ECDH between the Enclave private key for
        ``key_id`` and the supplied ``peer_pub`` (SEC1 uncompressed).

        This is the only authorization boundary in the Protocol — on
        macOS this invokes ``SecKeyCopyKeyExchangeResult`` which may
        prompt for Touch ID / Optic ID / passcode.

        Raises :class:`NativeBackendError` on denial (cancelled, auth
        failed, biometry change locked out, no passcode set). Raises
        :class:`WrapKeyNotFound` if the Keychain item is missing.
        """
        ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _key_id_hash(key_id: str) -> bytes:
    """SHA-256 prefix used both for the on-disk ``key_id_hash`` field and
    the audit-log identifier. 16 bytes for the blob, 8 bytes (hex
    encoded → 16 chars) for the audit log."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:KEY_ID_HASH_LEN]


def _audit_key_id_hex(key_id: str) -> str:
    """16-char hex prefix of ``SHA-256(key_id)`` for audit-log emission.

    Never use the full ``key_id`` in the audit log — POLICY.md code #19
    explicitly forbids it so consumers can rate-limit by hash without
    seeing the cleartext.
    """
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:8].hex()


def _build_hkdf_info(key_id_hash: bytes, ephemeral_pub: bytes) -> bytes:
    """Construct the HKDF ``info`` parameter that binds non-secret blob
    fields to the derived KEK (codex review HIGH-2).

    Layout: ``MAGIC || version(1) || alg_suite(1) || key_id_hash(16) ||
    ephemeral_pub(65)`` = 87 bytes. A tampered field produces a
    different ``info`` → different KEK → AES-KW unwrap fails the AIV
    check, giving us authenticated integrity despite AES-KW lacking AAD.
    """
    return MAGIC + bytes([VERSION, ALG_SUITE]) + key_id_hash + ephemeral_pub


def _derive_kek(shared_secret: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 with a zero-length salt, 32-byte output (AES-256)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def _decode_sec1_uncompressed_p256(point_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Strict SEC1 uncompressed P-256 decode.

    Rejects compressed (``0x02`` / ``0x03``) and hybrid (``0x06`` /
    ``0x07``) encodings — the wire format pins uncompressed (``0x04``).
    Off-curve points are rejected by ``from_encoded_point`` via the
    underlying OpenSSL EC_POINT validation.
    """
    if len(point_bytes) != EPHEMERAL_PUB_LEN or point_bytes[0] != 0x04:
        raise WrapParseError(
            "ephemeral_pub must be 65-byte SEC1 uncompressed (0x04 prefix); "
            f"got {len(point_bytes)} bytes starting with {point_bytes[:1]!r}"
        )
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point_bytes)
    except ValueError as exc:
        raise WrapParseError(f"ephemeral_pub is not a valid P-256 point: {exc}") from exc


class _ParsedHeader:
    """Holds the parsed-and-validated view of a 127-byte wrap blob.

    Attributes are positional bytes plus the decoded EC point object.
    Constructed only by :func:`_parse_header` — all validation happens
    there so callers can rely on every field being well-formed.
    """

    __slots__ = ("ephemeral_pub", "ephemeral_pub_obj", "key_id_hash", "wrapped_dek")

    def __init__(
        self,
        key_id_hash: bytes,
        ephemeral_pub: bytes,
        ephemeral_pub_obj: ec.EllipticCurvePublicKey,
        wrapped_dek: bytes,
    ) -> None:
        self.key_id_hash = key_id_hash
        self.ephemeral_pub = ephemeral_pub
        self.ephemeral_pub_obj = ephemeral_pub_obj
        self.wrapped_dek = wrapped_dek


def _parse_header(blob: bytes, key_id: str) -> _ParsedHeader:
    """Strict structural validation of a wrap blob.

    Every rejection is a :class:`WrapParseError` so callers can treat
    "this blob is invalid" as a single category. The check order is
    cheapest-first: length → magic → version → alg_suite → key_id_hash
    → ephemeral_pub SEC1 decode. This means a tampered byte is reported
    with the most specific failure mode available, but no Enclave call
    has happened yet.
    """
    if len(blob) != HEADER_LEN:
        raise WrapParseError(f"wrap blob must be exactly {HEADER_LEN} bytes for version=1; got {len(blob)}")

    magic = blob[_OFFSET_MAGIC:_OFFSET_VERSION]
    if magic != MAGIC:
        raise WrapParseError(f"bad magic: expected {MAGIC!r}, got {magic!r}")

    version = blob[_OFFSET_VERSION]
    if version != VERSION:
        raise WrapParseError(f"unsupported wrap blob version: {version} (this build expects {VERSION})")

    alg_suite = blob[_OFFSET_ALG_SUITE]
    if alg_suite != ALG_SUITE:
        raise WrapParseError(
            f"unsupported alg_suite: {alg_suite} (this build expects suite 1 = P256_ECDH_RAW + HKDF_SHA256 + AES256_KW)"
        )

    blob_kid_hash = blob[_OFFSET_KEY_ID_HASH:_OFFSET_EPHEMERAL_PUB]
    expected_kid_hash = _key_id_hash(key_id)
    if blob_kid_hash != expected_kid_hash:
        # NOTE: we report mismatch but do NOT include the cleartext
        # ``key_id`` in the message. Leaking it via error text would
        # defeat the POLICY.md #19 "never the cleartext key_id" rule.
        raise WrapParseError("key_id_hash mismatch — blob was wrapped for a different key_id")

    ephemeral_pub = blob[_OFFSET_EPHEMERAL_PUB:_OFFSET_WRAPPED_DEK]
    ephemeral_pub_obj = _decode_sec1_uncompressed_p256(ephemeral_pub)

    wrapped_dek = blob[_OFFSET_WRAPPED_DEK:]
    if len(wrapped_dek) != WRAPPED_DEK_LEN:
        # Unreachable given the HEADER_LEN check, but defensive.
        raise WrapParseError(f"wrapped_dek must be {WRAPPED_DEK_LEN} bytes; got {len(wrapped_dek)}")

    return _ParsedHeader(blob_kid_hash, ephemeral_pub, ephemeral_pub_obj, wrapped_dek)


def _emit_unwrap_denied(
    audit_sink: AuditSink,
    *,
    key_id: str,
    native_error_code: str,
) -> Exception | None:
    """Best-effort emit of the ``keyvault.unwrap_denied`` audit entry.

    Returns the sink's exception (if any, only :class:`Exception`
    subclasses) so the caller can chain it as ``__context__`` on the
    primary :class:`WrapAuthCancelled`. Mirrors PR2 ``recovery._emit_mismatch``
    (code-reviewer HIGH-1, 2026-05-14).

    The ``except Exception`` is intentional — we do NOT catch
    :class:`BaseException`. KeyboardInterrupt / SystemExit /
    GeneratorExit are control-flow exceptions that must propagate
    untouched so Ctrl-C handling in any CLI built on top of this module
    keeps working.
    """
    try:
        audit_sink(
            {
                "event": "keyvault.unwrap_dek",
                "decision": "block",
                "reason": "keyvault.unwrap_denied",
                "key_id_hash": _audit_key_id_hex(key_id),
                "native_error_code": native_error_code,
            }
        )
    except Exception as exc:
        return exc
    return None


# ---------------------------------------------------------------------------
# Public surface (PR3 step-0 SPEC freeze)
# ---------------------------------------------------------------------------


def generate_wrapping_key(key_id: str, *, backend: NativeBackend) -> None:
    """Create + persist a Secure-Enclave-backed P-256 keypair for ``key_id``.

    The public key remains exportable; the private key never leaves the
    Enclave. Raises :class:`WrapKeyNotFound` if a key with this id
    already exists in the Keychain (backend translates
    ``errSecDuplicateItem`` to this exception so callers do not need to
    know the OSStatus).
    """
    backend.generate_enclave_key(key_id)


def get_wrapping_key_public(key_id: str, *, backend: NativeBackend) -> bytes:
    """Return the SEC1 uncompressed P-256 public key (65 bytes) for ``key_id``.

    Raises :class:`WrapKeyNotFound` if the Keychain has no item. No
    Enclave authorization happens — public-key lookup is unprivileged.
    """
    return backend.get_enclave_public_key(key_id)


def delete_wrapping_key(key_id: str, *, backend: NativeBackend) -> None:
    """Remove the Keychain item for ``key_id``. Idempotent.

    Deleted keys cannot be recovered — any wrap blobs produced under
    ``key_id`` become permanently un-unwrappable. The caller is
    responsible for exporting backups (``api.export_backup``, Phase 4
    PR4) before invoking this.
    """
    backend.delete_enclave_key(key_id)


def wrap_dek(dek: bytes, key_id: str, *, backend: NativeBackend) -> bytes:
    """Wrap a 32-byte DEK under the Enclave-protected wrapping key.

    Offline — does NOT call ``enclave_ecdh`` and never prompts the user
    for authorization. Uses the cached Enclave public key + a freshly
    generated software ephemeral private key. Each call produces a
    different blob even for the same ``(dek, key_id)`` because the
    ephemeral keypair is fresh.

    Returns the 127-byte blob documented in SPEC.md §Wrap wire format.

    Raises :class:`WrapKeyNotFound` if the Keychain has no item for
    ``key_id``. Raises :class:`ValueError` if ``dek`` is not exactly
    ``DEK_LEN`` bytes.
    """
    if len(dek) != DEK_LEN:
        raise ValueError(f"DEK must be exactly {DEK_LEN} bytes; got {len(dek)}")

    enclave_pub_bytes = backend.get_enclave_public_key(key_id)
    enclave_pub = _decode_sec1_uncompressed_p256(enclave_pub_bytes)

    ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    shared_secret = ephemeral_priv.exchange(ec.ECDH(), enclave_pub)

    kid_hash = _key_id_hash(key_id)
    info = _build_hkdf_info(kid_hash, ephemeral_pub_bytes)
    kek = _derive_kek(shared_secret, info)

    wrapped_dek = aes_key_wrap(kek, dek)

    return MAGIC + bytes([VERSION, ALG_SUITE]) + kid_hash + ephemeral_pub_bytes + wrapped_dek


def unwrap_dek(
    blob: bytes,
    key_id: str,
    *,
    audit_sink: AuditSink,
    backend: NativeBackend,
) -> bytes:
    """Verify the blob and unwrap the DEK using the Enclave key.

    This is the authorization boundary — ``backend.enclave_ecdh`` calls
    ``SecKeyCopyKeyExchangeResult`` which may prompt the user. Emits
    exactly one of:

    - ``keyvault.unwrap_authorized`` (decision ``allow``) on success.
    - ``keyvault.unwrap_denied`` (decision ``block``) on auth failure.

    Raises:
        WrapParseError: blob is structurally invalid. Parse rejections
            happen BEFORE any Enclave call — UX + privacy (no biometric
            prompt for malformed blobs).
        WrapKeyNotFound: Keychain has no item for ``key_id``.
        WrapAuthCancelled: user denied the access-control prompt. The
            underlying :class:`NativeBackendError` is chained via
            ``__cause__``; if ``audit_sink`` itself raised while
            recording the denial, the sink exception is chained via
            ``__context__`` so callers' denial handlers stay correct
            (mirrors PR2 ``recovery.import_backup`` HIGH-1 fix).
        WrapIntegrityError: AES-KW AIV check failed — blob's
            ``ephemeral_pub`` or ``wrapped_dek`` was tampered with.

    The ``audit_sink`` is called at most once per invocation (success
    OR denial, never both). Integrity / parse / key-not-found failures
    do NOT emit any audit entry because they happen before the
    authorization decision is reached.
    """
    parsed = _parse_header(blob, key_id)

    denied: NativeBackendError | None = None
    shared_secret: bytes | None = None
    try:
        shared_secret = backend.enclave_ecdh(key_id, parsed.ephemeral_pub)
    except NativeBackendError as exc:
        denied = exc

    if denied is not None:
        # Emit + raise outside the ``except`` handler so that Python's
        # implicit ``__context__`` assignment (which would point at
        # ``denied`` itself) does not overwrite our explicit chain.
        # Pattern mirrors PR2 ``recovery.import_backup`` (code-reviewer
        # HIGH-1, 2026-05-14).
        sink_exc = _emit_unwrap_denied(audit_sink, key_id=key_id, native_error_code=denied.code)
        primary = WrapAuthCancelled(denied.code)
        primary.__cause__ = denied
        if sink_exc is not None:
            primary.__context__ = sink_exc
        raise primary

    assert shared_secret is not None  # narrow for mypy; denied is None implies success above
    info = _build_hkdf_info(parsed.key_id_hash, parsed.ephemeral_pub)
    kek = _derive_kek(shared_secret, info)

    try:
        dek = aes_key_unwrap(kek, parsed.wrapped_dek)
    except InvalidUnwrap as exc:
        raise WrapIntegrityError("AES-KW AIV check failed — wrapped_dek or ephemeral_pub was tampered with") from exc

    audit_sink(
        {
            "event": "keyvault.unwrap_dek",
            "decision": "allow",
            "reason": "keyvault.unwrap_authorized",
            "key_id_hash": _audit_key_id_hex(key_id),
        }
    )

    return dek
