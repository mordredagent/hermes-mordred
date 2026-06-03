"""Tests for Phase 4 production ``_SecKeyBackend``.

The pyobjc-touching ``_PyobjcSecKeyOps`` is covered only by the live
integration test (``tests/integration/test_keyvault_macos.py``). Here we
exercise the cross-platform half — ``_SecKeyBackend``'s flow + error
translation — by injecting a software-crypto ``_FakeOps`` that satisfies
the ``_SecKeyOps`` Protocol with real ``cryptography`` P-256 keys, so the
HKDF / AES-KW / wire-format paths run with real crypto (not mocks).
"""

from __future__ import annotations

import sys
from typing import Any, ClassVar

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

    def create_keypair(self, tag: bytes, label: str, *, unattended: bool = False) -> bytes:
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
    # Inject a software fake for the SW namespace too: the dual-namespace flow
    # (errSecItemNotFound fall-through, delete) otherwise reaches the real
    # _SoftwareFallbackOps → native._security, which only loads on macOS. With a
    # fake sw_ops the flow + error translation run cross-platform (green on Linux).
    return _SecKeyBackend(ops=ops, sw_ops=_FakeOps())


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
    """On Linux with no TPM helper, ``probe_capability`` fails closed with
    ``WrapNativeUnavailable`` (the dedicated Linux branch raises before ever
    touching ``_lazy_import_security``). ``native.is_secure_enclave_available``
    swallows that into ``False`` — verified in ``test_keyvault_native.py``;
    here we confirm the raise contract.

    Both helpers are patched out so the platform check is reached regardless
    of whether ``mordred-hermes-tpmkey`` is installed on the test machine
    (without the ``find_tpmkey_helper`` patch this test would try to exec a
    real helper if one happened to be installed)."""
    import sys

    import mordred_hermes.keyvault.native as native
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(native, "_security_module", None)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(_seckey_helper, "_find_helper", lambda: None)
    monkeypatch.setattr(_seckey_helper, "find_tpmkey_helper", lambda: None)
    with pytest.raises(WrapNativeUnavailable):
        probe_capability()


# These two assert the *macOS* default-ops wiring (no explicit ``ops=``), so
# they exercise the Darwin branch of ``_default_ops()``. Off Darwin that branch
# fails closed with ``WrapNativeUnavailable`` (no TPM helper) — the Linux wiring
# is covered instead by ``test_keyvault_tpm_dispatch.py``. Skip rather than
# fail on non-macOS CI.
_macos_only = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS default-ops wiring; Linux fail-closed branch covered in test_keyvault_tpm_dispatch.py",
)


@_macos_only
def test_pyobjc_ops_is_default_backend_ops_no_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the signed helper is absent, ``_SecKeyBackend()`` wires the
    in-process pyobjc bridge (``_PyobjcSecKeyOps``)."""
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(_seckey_helper, "_find_helper", lambda: None)
    real = _SecKeyBackend()
    assert isinstance(real._ops, _PyobjcSecKeyOps)


@_macos_only
def test_helper_ops_is_default_backend_ops_when_helper_present(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """When the signed helper is present, ``_SecKeyBackend()`` wires
    ``_HelperSecKeyOps`` instead of ``_PyobjcSecKeyOps``."""
    from mordred_hermes.keyvault import _seckey_helper
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    fake = tmp_path / "fake-helper"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setattr(_seckey_helper, "_find_helper", lambda: str(fake))
    real = _SecKeyBackend()
    assert isinstance(real._ops, _HelperSecKeyOps)


# ---------------------------------------------------------------------------
# _PyobjcSecKeyOps — pyobjc bridge error containment
# ---------------------------------------------------------------------------


class _BridgeSentinel:
    """Any attribute access returns a unique sentinel value.

    Stand-in for the CFString constants the production code reads off the
    pyobjc ``Security`` module (``kSecAttrKeyType``, ``kSecPrivateKeyAttrs``
    …). ``kSecAccessControl*`` names get distinct ``int`` powers-of-two so
    the production code's bit-OR (``flags | sec.kSecAccessControlBiometry…``)
    works; everything else is a unique str so dict-build paths still work.
    """

    _bits: ClassVar[dict[str, int]] = {}

    def __getattr__(self, name: str) -> Any:
        if name.startswith("kSecAccessControl"):
            bit = self._bits.get(name)
            if bit is None:
                bit = 1 << len(self._bits)
                self._bits[name] = bit
            return bit
        return f"<sentinel:{name}>"


def _make_bridge_fake(raise_exc: Exception) -> Any:
    """Build a fake pyobjc ``Security`` module whose
    ``SecKeyCreateRandomKey`` raises ``raise_exc``.

    Mirrors the in-the-wild pyobjc bridge regression observed against
    Apple's Secure Enclave: the bridge can raise opaque ``KeyError`` /
    ``TypeError`` from inside the C extension before the Python caller
    ever sees a ``(None, NSError)`` tuple.
    """

    class _Fake(_BridgeSentinel):
        def SecAccessControlCreateWithFlags(
            self,
            _allocator: Any,
            _protection: Any,
            _flags: Any,
            _error: Any,
        ) -> tuple[Any, Any]:
            return ("<access-control>", None)

        def SecKeyCreateRandomKey(self, _attrs: Any, _error: Any) -> Any:
            raise raise_exc

    return _Fake()


def _install_bridge_fake(monkeypatch: pytest.MonkeyPatch, raise_exc: Exception) -> None:
    """Inject ``_make_bridge_fake(raise_exc)`` as the cached Security module."""
    import mordred_hermes.keyvault.native as native

    monkeypatch.setattr(native, "_security_module", _make_bridge_fake(raise_exc))


@pytest.mark.parametrize(
    ("raise_exc", "fragment"),
    [
        (KeyError("public"), "public"),  # the canonical observed regression
        (KeyError("private"), "private"),  # token-ID path variant
        (KeyError("applepay"), "applepay"),  # recursive bridge lookup variant
        (TypeError("Need 2 arguments, got 1"), "Need 2 arguments"),
    ],
)
def test_pyobjc_ops_create_wraps_bridge_errors_as_ops_error(
    monkeypatch: pytest.MonkeyPatch,
    raise_exc: Exception,
    fragment: str,
) -> None:
    """``KeyError`` / ``TypeError`` leaking from the SecKey-creation
    code path must be wrapped as :class:`_OpsError` with the
    ``pyobjc-bridge`` domain so ``_SecKeyBackend`` can translate it to
    ``WrapError`` and ``init_keyvault`` does not leave partial state
    behind.

    Post-Phase-3, ``_PyobjcSecKeyOps._create`` routes through
    :func:`_seckey_ctypes.create_random_key_via_ctypes` instead of
    ``sec.SecKeyCreateRandomKey``, so the bridge bug can no longer
    surface via the legacy call site. The wrapper is kept as
    defence-in-depth in case a future regression slips a pyobjc dict
    back into the path. This test installs a fake ctypes helper that
    raises the historically observed bridge exceptions and asserts the
    wrapper still translates them.
    """
    from mordred_hermes.keyvault import _seckey_ctypes

    # Need a fake `sec` for the upstream `_access_control` call before
    # the ctypes helper runs — the bridge fake provides
    # SecAccessControlCreateWithFlags returning a sentinel.
    _install_bridge_fake(monkeypatch, raise_exc)

    def _raising_ctypes_helper(_sec: Any, _attrs: Any) -> tuple[Any, Any]:
        raise raise_exc

    monkeypatch.setattr(_seckey_ctypes, "create_random_key_via_ctypes", _raising_ctypes_helper)

    ops = _PyobjcSecKeyOps()

    with pytest.raises(_OpsError) as excinfo:
        ops.create_keypair(b"tag", "label")

    assert excinfo.value.domain == "pyobjc-bridge"
    assert excinfo.value.__cause__ is raise_exc
    assert fragment in str(excinfo.value)


def test_keychain_query_does_not_request_data_protection_keychain() -> None:
    """Phase 4: ``_keychain_query`` must not pin
    ``kSecUseDataProtectionKeychain=True``. The Data Protection Keychain
    requires the ``keychain-access-groups`` entitlement, which an
    unsigned local Python interpreter does not carry, so writes fail
    with ``errSecMissingEntitlement (-34018)``. Phase 4 switches to the
    legacy macOS keychain so each developer can run ``keyvault init``
    locally without code-signing infrastructure.

    The codex-review HIGH invariant (every ``SecItem*`` op must target
    the same keychain) is still satisfied — uniformly via the legacy
    keychain instead of uniformly via the Data Protection Keychain.
    """
    sec = pytest.importorskip("Security")

    from mordred_hermes.keyvault._seckey_backend import _keychain_query

    query = _keychain_query(sec, b"mordred-hermes.test-tag")
    assert sec.kSecUseDataProtectionKeychain not in query, (
        "Phase 4 removed the Data Protection Keychain dependency; "
        "_keychain_query must not pin kSecUseDataProtectionKeychain=True."
    )


def test_pyobjc_ops_create_attrs_do_not_request_data_protection_keychain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 4 mirror of :func:`test_keychain_query_does_not_request_data_protection_keychain`
    for the write side: ``_PyobjcSecKeyOps._create`` must not include
    ``kSecUseDataProtectionKeychain=True`` in the attrs passed to
    ``SecKeyCreateRandomKey``. We capture attrs via the ctypes helper
    seam instead of touching the real Security framework.
    """
    sec = pytest.importorskip("Security")

    import contextlib

    from mordred_hermes.keyvault import _seckey_ctypes
    from mordred_hermes.keyvault._seckey_backend import _OpsError, _PyobjcSecKeyOps

    captured: list[dict] = []

    def _capture(_sec: Any, attrs: dict) -> tuple[Any, Any]:
        captured.append(attrs)
        return None, None  # benign — _create will raise _OpsError after this

    monkeypatch.setattr(_seckey_ctypes, "create_random_key_via_ctypes", _capture)

    ops = _PyobjcSecKeyOps()
    with contextlib.suppress(_OpsError):
        ops.create_keypair(b"mordred-hermes.test-tag", "Phase 4 attrs probe")

    assert captured, "ctypes helper was not invoked by _PyobjcSecKeyOps._create"
    attrs = captured[0]
    assert sec.kSecUseDataProtectionKeychain not in attrs, (
        "Phase 4 removed the Data Protection Keychain dependency; "
        "_create attrs must not request kSecUseDataProtectionKeychain=True."
    )


def test_pyobjc_bridge_keyerror_surfaces_as_wrap_error_through_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense-in-depth: a pyobjc bridge ``KeyError`` reaching the
    backend must come out as :class:`WrapError`, not propagate through.

    This is the contract :func:`init_keyvault` relies on to roll back
    partial Secure-Enclave / ciphertext / digest writes.
    """
    from mordred_hermes.keyvault import _seckey_ctypes

    raise_exc = KeyError("public")
    _install_bridge_fake(monkeypatch, raise_exc)

    def _raising_ctypes_helper(_sec: Any, _attrs: Any) -> tuple[Any, Any]:
        raise raise_exc

    monkeypatch.setattr(_seckey_ctypes, "create_random_key_via_ctypes", _raising_ctypes_helper)

    backend = _SecKeyBackend(ops=_PyobjcSecKeyOps())

    with pytest.raises(WrapError) as excinfo:
        backend.generate_enclave_key("wallet-key")

    assert not isinstance(excinfo.value, WrapKeyNotFound)
    assert isinstance(excinfo.value.__cause__, _OpsError)
    assert excinfo.value.__cause__.domain == "pyobjc-bridge"
