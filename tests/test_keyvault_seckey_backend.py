"""Tests for Phase 4 production ``_SecKeyBackend``.

The pyobjc-touching ``_PyobjcSecKeyOps`` is covered only by the live
integration test (``tests/integration/test_keyvault_macos.py``). Here we
exercise the cross-platform half — ``_SecKeyBackend``'s flow + error
translation — by injecting a software-crypto ``_FakeOps`` that satisfies
the ``_SecKeyOps`` Protocol with real ``cryptography`` P-256 keys, so the
HKDF / AES-KW / wire-format paths run with real crypto (not mocks).
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.keyvault import wrap
from mordred_hermes.keyvault._exceptions import WrapError, WrapKeyNotFound, WrapNativeUnavailable
from mordred_hermes.keyvault._seckey_backend import (
    _application_tag,
    _keychain_label,
    _OpsError,
    _PyobjcSecKeyOps,
    _SecKeyBackend,
    _translate_error,
    errSecAuthFailed,
    errSecAuthorizationCanceled,
    errSecDuplicateItem,
    errSecInteractionNotAllowed,
    errSecItemNotFound,
    errSecUserCanceled,
    probe_capability,
)
from mordred_hermes.keyvault.wrap import NativeBackend, NativeBackendError

# ---------------------------------------------------------------------------
# Software-crypto fake for the _SecKeyOps boundary
# ---------------------------------------------------------------------------


class _FakeOps:
    """Software P-256 stand-in for the Secure Enclave (``_SecKeyOps``).

    Each ``tag`` maps to a real ``cryptography`` private key, so a full
    ``wrap_dek`` → ``unwrap_dek`` round-trip through ``_SecKeyBackend``
    exercises genuine ECDH / HKDF / AES-KW. Failure paths are simulated
    by assigning the ``*_error`` attributes before a call.
    """

    def __init__(self) -> None:
        self._keys: dict[bytes, ec.EllipticCurvePrivateKey] = {}
        self.calls: list[tuple[str, bytes]] = []
        self.create_error: _OpsError | None = None
        self.copy_error: _OpsError | None = None
        self.delete_error: _OpsError | None = None
        self.exchange_error: _OpsError | None = None

    def create_keypair(self, tag: bytes, label: str) -> bytes:
        self.calls.append(("create", tag))
        if self.create_error is not None:
            raise self.create_error
        if tag in self._keys:
            raise _OpsError(errSecDuplicateItem)
        priv = ec.generate_private_key(ec.SECP256R1())
        self._keys[tag] = priv
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def copy_public_key(self, tag: bytes) -> bytes:
        self.calls.append(("copy_pub", tag))
        if self.copy_error is not None:
            raise self.copy_error
        if tag not in self._keys:
            raise _OpsError(errSecItemNotFound)
        return self._keys[tag].public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def delete_key(self, tag: bytes) -> None:
        self.calls.append(("delete", tag))
        if self.delete_error is not None:
            raise self.delete_error
        self._keys.pop(tag, None)  # idempotent — mirrors errSecItemNotFound==success

    def key_exchange(self, tag: bytes, peer_pub: bytes) -> bytes:
        self.calls.append(("ecdh", tag))
        if self.exchange_error is not None:
            raise self.exchange_error
        if tag not in self._keys:
            raise _OpsError(errSecItemNotFound)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self._keys[tag].exchange(ec.ECDH(), peer)


@pytest.fixture
def ops() -> _FakeOps:
    return _FakeOps()


@pytest.fixture
def backend(ops: _FakeOps) -> _SecKeyBackend:
    return _SecKeyBackend(ops=ops)


# ---------------------------------------------------------------------------
# Module hygiene
# ---------------------------------------------------------------------------


def test_module_imports_on_any_platform() -> None:
    """``_seckey_backend`` must import without pyobjc — it reaches the
    bridge only through ``native._lazy_import_security`` at call time."""
    import mordred_hermes.keyvault._seckey_backend  # noqa: F401


def test_backend_satisfies_native_backend_protocol(backend: _SecKeyBackend) -> None:
    """The whole point of the class: it is a structural ``NativeBackend``
    so ``api.confirm_generate(*, backend=...)`` accepts it."""
    assert isinstance(backend, NativeBackend)


# ---------------------------------------------------------------------------
# Keychain tag / label construction
# ---------------------------------------------------------------------------


def test_application_tag_is_namespaced_and_hides_cleartext_key_id() -> None:
    """SPEC.md: ``kSecAttrApplicationTag = b"mordred-hermes.wrap." +
    key_id_hash``. The cleartext key_id must never appear (POLICY.md #19)."""
    tag = _application_tag("my-secret-wallet")
    assert tag.startswith(b"mordred-hermes.wrap.")
    assert b"my-secret-wallet" not in tag
    assert tag[len(b"mordred-hermes.wrap.") :] == wrap._key_id_hash("my-secret-wallet")


def test_application_tag_deterministic_and_distinct() -> None:
    assert _application_tag("k1") == _application_tag("k1")
    assert _application_tag("k1") != _application_tag("k2")


def test_keychain_label_is_human_readable_hash_prefix() -> None:
    label = _keychain_label("k1")
    assert label.startswith("Mordred wrapping key ")
    assert "k1" not in label.removeprefix("Mordred wrapping key ")


# ---------------------------------------------------------------------------
# OSStatus / LAError translation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (errSecUserCanceled, "user_cancelled"),
        (errSecAuthorizationCanceled, "user_cancelled"),
        (errSecAuthFailed, "auth_failed"),
        (errSecItemNotFound, "key_not_found"),
        (errSecInteractionNotAllowed, "biometry_lockout"),
        (-99999, "auth_failed"),  # unknown OSStatus → conservative default
    ],
)
def test_translate_osstatus_domain(status: int, expected: str) -> None:
    assert _translate_error(status, "OSStatus") == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (-2, "user_cancelled"),  # LAErrorUserCancel
        (-3, "user_cancelled"),  # LAErrorUserFallback
        (-4, "user_cancelled"),  # LAErrorSystemCancel
        (-1, "auth_failed"),  # LAErrorAuthenticationFailed
        (-5, "passcode_not_set"),  # LAErrorPasscodeNotSet
        (-8, "biometry_lockout"),  # LAErrorBiometryLockout
        (-6, "auth_failed"),  # LAErrorBiometryNotAvailable
        (-12345, "auth_failed"),  # unknown LAError → conservative default
    ],
)
def test_translate_la_error_domain(status: int, expected: str) -> None:
    assert _translate_error(status, "com.apple.LocalAuthentication") == expected


def test_translate_error_only_returns_frozen_codes() -> None:
    """Every translation output must be inside the frozen NativeErrorCode
    set — a raw OSStatus must never reach a NativeBackendError."""
    for status, domain in [(-128, "OSStatus"), (-2, "com.apple.LocalAuthentication"), (777, "x")]:
        assert _translate_error(status, domain) in wrap._NATIVE_ERROR_CODES


# ---------------------------------------------------------------------------
# generate_enclave_key
# ---------------------------------------------------------------------------


def test_generate_returns_sec1_uncompressed_public_key(backend: _SecKeyBackend) -> None:
    pub = backend.generate_enclave_key("k1")
    assert len(pub) == 65 and pub[0] == 0x04


def test_generate_duplicate_tag_raises_wrap_key_not_found(backend: _SecKeyBackend) -> None:
    backend.generate_enclave_key("k1")
    with pytest.raises(WrapKeyNotFound):
        backend.generate_enclave_key("k1")


def test_generate_other_native_error_raises_wrap_error(ops: _FakeOps, backend: _SecKeyBackend) -> None:
    ops.create_error = _OpsError(errSecAuthFailed, "OSStatus")
    with pytest.raises(WrapError) as excinfo:
        backend.generate_enclave_key("k1")
    assert not isinstance(excinfo.value, WrapKeyNotFound)
    assert isinstance(excinfo.value.__cause__, _OpsError)


# ---------------------------------------------------------------------------
# get_enclave_public_key
# ---------------------------------------------------------------------------


def test_get_public_key_round_trips_generate(backend: _SecKeyBackend) -> None:
    generated = backend.generate_enclave_key("k1")
    assert backend.get_enclave_public_key("k1") == generated


def test_get_public_key_missing_raises_wrap_key_not_found(backend: _SecKeyBackend) -> None:
    with pytest.raises(WrapKeyNotFound):
        backend.get_enclave_public_key("never-generated")


def test_get_public_key_other_error_raises_wrap_error(ops: _FakeOps, backend: _SecKeyBackend) -> None:
    ops.copy_error = _OpsError(errSecAuthFailed, "OSStatus")
    with pytest.raises(WrapError) as excinfo:
        backend.get_enclave_public_key("k1")
    assert not isinstance(excinfo.value, WrapKeyNotFound)


# ---------------------------------------------------------------------------
# delete_enclave_key
# ---------------------------------------------------------------------------


def test_delete_is_idempotent_when_key_absent(backend: _SecKeyBackend) -> None:
    # No raise — delete of a never-generated key is a contractual no-op.
    backend.delete_enclave_key("never-generated")


def test_delete_removes_generated_key(backend: _SecKeyBackend) -> None:
    backend.generate_enclave_key("k1")
    backend.delete_enclave_key("k1")
    with pytest.raises(WrapKeyNotFound):
        backend.get_enclave_public_key("k1")


def test_delete_other_error_raises_wrap_error(ops: _FakeOps, backend: _SecKeyBackend) -> None:
    ops.delete_error = _OpsError(errSecAuthFailed, "OSStatus")
    with pytest.raises(WrapError):
        backend.delete_enclave_key("k1")


# ---------------------------------------------------------------------------
# enclave_ecdh — the authorization boundary
# ---------------------------------------------------------------------------


def _peer_pub() -> bytes:
    return (
        ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    )


def test_ecdh_returns_shared_secret(backend: _SecKeyBackend) -> None:
    backend.generate_enclave_key("k1")
    shared = backend.enclave_ecdh("k1", _peer_pub())
    assert isinstance(shared, bytes) and len(shared) == 32


def test_ecdh_missing_key_raises_wrap_key_not_found(backend: _SecKeyBackend) -> None:
    """Missing key is pre-authorization — surfaces as WrapKeyNotFound so
    ``unwrap_dek`` emits no audit entry (SPEC.md unwrap step 2)."""
    with pytest.raises(WrapKeyNotFound):
        backend.enclave_ecdh("never-generated", _peer_pub())


@pytest.mark.parametrize(
    ("status", "domain", "expected_code"),
    [
        (errSecUserCanceled, "OSStatus", "user_cancelled"),
        (errSecAuthFailed, "OSStatus", "auth_failed"),
        (errSecInteractionNotAllowed, "OSStatus", "biometry_lockout"),
        (-5, "com.apple.LocalAuthentication", "passcode_not_set"),
        (-8, "com.apple.LocalAuthentication", "biometry_lockout"),
    ],
)
def test_ecdh_denial_raises_native_backend_error_with_translated_code(
    ops: _FakeOps,
    backend: _SecKeyBackend,
    status: int,
    domain: str,
    expected_code: str,
) -> None:
    backend.generate_enclave_key("k1")
    ops.exchange_error = _OpsError(status, domain)
    with pytest.raises(NativeBackendError) as excinfo:
        backend.enclave_ecdh("k1", _peer_pub())
    assert excinfo.value.code == expected_code
    assert isinstance(excinfo.value.__cause__, _OpsError)


# ---------------------------------------------------------------------------
# End-to-end: wrap_dek → unwrap_dek through _SecKeyBackend
# ---------------------------------------------------------------------------


def test_wrap_unwrap_roundtrip_through_seckey_backend(backend: _SecKeyBackend) -> None:
    """The backend's whole job: drive ``wrap.wrap_dek`` / ``unwrap_dek``
    end-to-end. Uses real ECDH (via _FakeOps' cryptography keys) so HKDF
    + AES-KW + the 127-byte wire format are all exercised."""
    audit: list[dict[str, Any]] = []
    dek = bytes(range(32))

    wrap.generate_wrapping_key("wallet-key", backend=backend)
    blob = wrap.wrap_dek(dek, "wallet-key", backend=backend)
    assert len(blob) == wrap.HEADER_LEN

    recovered = wrap.unwrap_dek(blob, "wallet-key", audit_sink=audit.append, backend=backend)
    assert recovered == dek
    assert audit and audit[-1]["reason"] == "keyvault.unwrap_authorized"


def test_unwrap_denial_emits_audit_through_seckey_backend(ops: _FakeOps, backend: _SecKeyBackend) -> None:
    audit: list[dict[str, Any]] = []
    dek = bytes(range(32))
    wrap.generate_wrapping_key("wallet-key", backend=backend)
    blob = wrap.wrap_dek(dek, "wallet-key", backend=backend)

    ops.exchange_error = _OpsError(errSecUserCanceled, "OSStatus")
    with pytest.raises(WrapError):
        wrap.unwrap_dek(blob, "wallet-key", audit_sink=audit.append, backend=backend)
    assert audit and audit[-1]["reason"] == "keyvault.unwrap_denied"
    assert audit[-1]["native_error_code"] == "user_cancelled"


# ---------------------------------------------------------------------------
# probe_capability — production path is unavailable off-macOS
# ---------------------------------------------------------------------------


def test_probe_capability_raises_native_unavailable_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    """On non-Darwin, ``probe_capability`` reaches ``_lazy_import_security``
    which short-circuits to ``WrapNativeUnavailable``. ``native.is_secure_
    enclave_available`` swallows that into ``False`` — verified in
    ``test_keyvault_native.py``; here we confirm the raise contract."""
    import sys

    import mordred_hermes.keyvault.native as native

    monkeypatch.setattr(native, "_security_module", None)
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(WrapNativeUnavailable):
        probe_capability()


def test_pyobjc_ops_is_default_backend_ops() -> None:
    """Constructing ``_SecKeyBackend()`` with no ``ops`` wires the real
    pyobjc bridge — importing it must not touch pyobjc."""
    real = _SecKeyBackend()
    assert isinstance(real._ops, _PyobjcSecKeyOps)
