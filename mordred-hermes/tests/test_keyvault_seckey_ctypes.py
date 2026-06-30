"""Unit tests for the ctypes Secure-Enclave bypass.

The ``mordred_hermes.keyvault._seckey_ctypes`` module replaces
``sec.SecKeyCreateRandomKey(attrs, None)`` with a pure-ctypes call so
the pyobjc-framework-Security bridge bug (bare ``KeyError`` from the C
extension for CFString constants ``'public'`` / ``'private'`` /
``'applepay'`` when ``kSecAttrTokenIDSecureEnclave`` is requested) is
fully bypassed. The fix's hot path requires:

1. Building the ``attrs`` dictionary as a pure ``CFDictionary`` via
   ``CFDictionaryCreate`` — a pyobjc-managed ``NSDictionary`` is itself
   the bridge-bug trigger (verified in Phase 3 exploration).
2. Calling ``SecKeyCreateRandomKey`` through ``ctypes.CDLL`` so the
   bridge's metadata layer never participates.
3. Wrapping the returned ``SecKeyRef`` back as a pyobjc object so the
   downstream ``SecKeyCopyPublicKey`` / ``SecKeyCopyExternalRepresentation``
   calls — which do *not* trigger the bridge bug — keep working unchanged.

The macOS-gated integration smoke test below exercises a real Secure-Enclave
key generation (``.privateKeyUsage`` only, no biometry → no Touch ID prompt)
so the helper's RED→GREEN cycle is observable on the developer machine without
making the default unit suite depend on local hardware / sandbox access.
"""

from __future__ import annotations

import secrets
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="ctypes Secure-Enclave bypass is macOS-only (Security.framework)",
)


def _import_helper():
    """Lazy import so the module-level ``skipif`` fires before the import
    is attempted on a non-Darwin host (where the helper does not exist)."""
    from mordred_hermes.keyvault._seckey_ctypes import create_random_key_via_ctypes

    return create_random_key_via_ctypes


def _build_enclave_attrs(sec, *, tag: bytes, persist: bool):
    """Build the same attrs shape `_PyobjcSecKeyOps._create` uses."""
    access, ac_err = sec.SecAccessControlCreateWithFlags(
        None,
        sec.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        sec.kSecAccessControlPrivateKeyUsage,  # biometry=False → no Touch ID prompt
        None,
    )
    assert access is not None, f"SecAccessControl build failed: {ac_err!r}"
    private_key_attrs = {
        sec.kSecAttrIsPermanent: persist,
        sec.kSecAttrApplicationTag: tag,
        sec.kSecAttrLabel: "Mordred ctypes unit test",
        sec.kSecAttrAccessControl: access,
    }
    return {
        sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
        sec.kSecAttrKeySizeInBits: 256,
        sec.kSecAttrTokenID: sec.kSecAttrTokenIDSecureEnclave,
        # Phase 4: legacy macOS Keychain (no kSecUseDataProtectionKeychain).
        sec.kSecPrivateKeyAttrs: private_key_attrs,
    }


@pytest.mark.integration
def test_create_random_key_via_ctypes_generates_real_enclave_key() -> None:
    """End-to-end smoke: pure-ctypes path produces a real Secure-Enclave
    ``SecKeyRef`` with no ``KeyError`` from the pyobjc bridge.

    Equivalent attrs going through ``sec.SecKeyCreateRandomKey(attrs, None)``
    crash with ``KeyError('public')``; the ctypes helper must return a
    non-``None`` key.
    """
    create_random_key_via_ctypes = _import_helper()
    import Security as sec

    tag = b"mordred-itest-ctypes-" + secrets.token_bytes(8)
    attrs = _build_enclave_attrs(sec, tag=tag, persist=False)

    key, err = create_random_key_via_ctypes(sec, attrs)

    assert err is None, f"ctypes path returned error: {err!r}"
    assert key is not None
    pub = sec.SecKeyCopyPublicKey(key)
    assert pub is not None


def test_create_random_key_via_ctypes_returns_error_on_invalid_attrs() -> None:
    """Error contract: on a malformed attrs dict the helper must return
    ``(None, CFErrorRef-wrapped)`` — never raise — so the caller's
    ``_OpsError`` translator can run uniformly with both the legacy and
    ctypes paths.
    """
    create_random_key_via_ctypes = _import_helper()
    import Security as sec

    # Missing kSecAttrKeyType → framework rejects with errSecParam
    attrs = {sec.kSecAttrKeySizeInBits: 256}

    key, err = create_random_key_via_ctypes(sec, attrs)

    assert key is None
    assert err is not None


def test_pyobjc_ops_create_routes_through_ctypes_not_sec_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_PyobjcSecKeyOps._create`` must call the ctypes helper, not
    ``sec.SecKeyCreateRandomKey``. We count calls to the pyobjc bridge
    function — any call from ``_create`` proves the ctypes bypass is
    not in effect.

    The actual keypair generation is allowed to fail in this test: an
    unsigned Python interpreter cannot persist to the Data Protection
    Keychain (``errSecMissingEntitlement = -34018``). That is an
    orthogonal real-world limitation; the routing assertion is what
    this regression guard protects.
    """
    import contextlib

    import Security as sec

    from mordred_hermes.keyvault._seckey_backend import _OpsError, _PyobjcSecKeyOps

    bridge_calls: list[tuple] = []

    def _trap(*args: object, **_kw: object) -> object:
        bridge_calls.append(args)
        return None  # don't raise — we just need to count, not blow up flow

    monkeypatch.setattr(sec, "SecKeyCreateRandomKey", _trap, raising=True)

    ops = _PyobjcSecKeyOps()
    tag = b"mordred-itest-route-" + secrets.token_bytes(8)
    with contextlib.suppress(_OpsError):
        ops.create_keypair(tag, "Mordred ctypes route guard")

    assert bridge_calls == [], (
        "sec.SecKeyCreateRandomKey was called from _PyobjcSecKeyOps._create "
        "— the ctypes bypass is bypassed and the pyobjc bridge bug can recur."
    )
