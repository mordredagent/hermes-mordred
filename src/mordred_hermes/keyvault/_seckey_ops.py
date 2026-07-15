"""pyobjc-touching Secure-Enclave I/O ops — the narrow ``_SecKeyOps`` boundary.

Extracted from :mod:`._seckey_backend` (which holds the flow + error-mapping
:class:`._seckey_backend._SecKeyBackend`) to keep each module under the size
guideline. This is *layer 1* of the design described in ``_seckey_backend``'s
module docstring: the narrowest possible ``Security.framework``-touching
surface. Every method returns plain ``bytes`` / ``None`` or raises
:class:`._seckey_errors._OpsError`; no ``Security.framework`` object ever
crosses this boundary, so :class:`._seckey_backend._SecKeyBackend` — which holds
all the flow and error-mapping logic — is fully testable with a fake
``_SecKeyOps`` on any platform.

The pyobjc bridge is reached exclusively through
:func:`mordred_hermes.keyvault.native._lazy_import_security`, so this module
imports cleanly on Linux / Windows just like ``native.py``.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any, Protocol

from . import native
from ._seckey_errors import (
    _PROBE_TAG_PREFIX,
    _SW_TAG_PREFIX,
    _OpsError,
    errSecAuthFailed,
    errSecItemNotFound,
    errSecSuccess,
)

# ---------------------------------------------------------------------------
# pyobjc-touching boundary
# ---------------------------------------------------------------------------


class _SecKeyOps(Protocol):
    """Narrowest Secure-Enclave I/O surface (dependency-injection seam).

    Every method either returns plain ``bytes`` / ``None`` or raises
    :class:`_OpsError`. No ``Security.framework`` object crosses this
    boundary, so :class:`_SecKeyBackend` — which holds all the flow and
    error-mapping logic — is fully testable with a fake ops on any
    platform.
    """

    def create_keypair(self, tag: bytes, label: str, *, unattended: bool = False) -> bytes:
        """Generate a permanent Secure-Enclave P-256 keypair tagged
        ``tag`` and return the SEC1 uncompressed public key (65 bytes).

        ``unattended=False`` (default) gates the private key behind a
        Touch ID / passcode access control, so every ECDH prompts.
        ``unattended=True`` creates a ``.privateKeyUsage``-only key:
        still Enclave-bound (non-exportable) but usable without a prompt
        while the session is unlocked, for autonomous flows.

        Raises :class:`_OpsError` (``errSecDuplicateItem`` if the tag is
        already taken)."""
        ...

    def copy_public_key(self, tag: bytes) -> bytes:
        """Return the SEC1 uncompressed public key for ``tag``. Raises
        :class:`_OpsError` (``errSecItemNotFound`` when absent)."""
        ...

    def delete_key(self, tag: bytes) -> None:
        """Remove the Keychain item for ``tag``. Idempotent — a missing
        item is success, not an :class:`_OpsError`."""
        ...

    def key_exchange(self, tag: bytes, peer_pub: bytes) -> bytes:
        """Raw ECDH between the Enclave private key for ``tag`` and the
        SEC1 ``peer_pub``. This is the authorization boundary — on macOS
        it triggers the Touch ID / passcode prompt. Raises
        :class:`_OpsError` on denial or a missing key."""
        ...


class _PyobjcSecKeyOps:
    """In-process :class:`_SecKeyOps` — real ``Security.framework`` calls.

    The fallback path used only when the signed ``mordred-hermes-sekey``
    helper is absent (see :func:`._seckey_backend._default_ops` and the
    ``_seckey_backend`` "Backend selection" note): it persists a real
    Secure-Enclave key only on an *entitled* interpreter, otherwise
    :class:`_SecKeyBackend` degrades to software P-256 on
    ``errSecMissingEntitlement``. Exercised only by the live integration
    test. Every method resolves the pyobjc ``Security`` module lazily via
    :func:`native._lazy_import_security`, so importing this class costs
    nothing on a non-macOS host.
    """

    def _security(self) -> Any:
        return native._lazy_import_security()

    def _access_control(self, sec: Any, *, biometry: bool) -> Any:
        """Build a ``SecAccessControl`` for the private key.

        ``biometry=True`` adds ``.biometryCurrentSet`` so the key is
        invalidated when the user's enrolled biometrics change (SPEC.md
        review MEDIUM-2). The capability probe passes ``biometry=False``
        — ``.privateKeyUsage`` alone never prompts.
        """
        flags = sec.kSecAccessControlPrivateKeyUsage
        if biometry:
            flags = flags | sec.kSecAccessControlBiometryCurrentSet
        access, err = sec.SecAccessControlCreateWithFlags(
            None,
            sec.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            flags,
            None,
        )
        if access is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecAccessControlCreateWithFlags failed")
        return access

    def _create(self, tag: bytes, label: str, *, biometry: bool) -> bytes:
        sec = self._security()
        access = self._access_control(sec, biometry=biometry)
        # kSecAttrLabel goes inside kSecPrivateKeyAttrs (not the top-level
        # generation dict) so it is actually attached to the stored
        # private-key Keychain item — mirrors Apple's Secure-Enclave key
        # generation pattern.
        private_key_attrs = {
            sec.kSecAttrIsPermanent: True,
            sec.kSecAttrApplicationTag: tag,
            sec.kSecAttrLabel: label,
            sec.kSecAttrAccessControl: access,
        }
        attrs = {
            sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
            sec.kSecAttrKeySizeInBits: 256,
            sec.kSecAttrTokenID: sec.kSecAttrTokenIDSecureEnclave,
            # In-process fallback path (see module "Backend selection"):
            # persist to the legacy macOS Keychain. The Data
            # Protection Keychain (kSecUseDataProtectionKeychain=True)
            # requires the keychain-access-groups entitlement, which an
            # unsigned local Python interpreter cannot carry — writes
            # fail with errSecMissingEntitlement (-34018). The codex-
            # review HIGH invariant (every SecItem* op targets the same
            # keychain) is still satisfied uniformly via the legacy
            # keychain; see _keychain_query.
            sec.kSecPrivateKeyAttrs: private_key_attrs,
        }
        # Phase 3 — route SecKeyCreateRandomKey through a pure-ctypes
        # CoreFoundation path to bypass the pyobjc-framework-Security
        # bridge bug entirely. The bug surfaces during framework-internal
        # CFDictionaryGetValue probes on the attrs dict and is the reason
        # ``sec.SecKeyCreateRandomKey(attrs, None)`` raises a bare
        # KeyError('public'). See ``_seckey_ctypes`` for details.
        #
        # The legacy try/except (KeyError, TypeError) wrapper is kept as
        # defence-in-depth: ``create_random_key_via_ctypes`` never raises
        # those on a healthy macOS host, but if a future regression slips
        # the bridge back into the path we still get a clean WrapError
        # rather than a partial-write crash.
        from . import _seckey_ctypes

        try:
            private_key, err = _seckey_ctypes.create_random_key_via_ctypes(sec, attrs)
        except (KeyError, TypeError) as exc:
            raise _OpsError(
                -1,
                "pyobjc-bridge",
                f"SecKeyCreateRandomKey bridge error: {exc!r}",
            ) from exc
        if private_key is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCreateRandomKey failed")
        public_key = sec.SecKeyCopyPublicKey(private_key)
        return _export_public_key(sec, public_key)

    def create_keypair(self, tag: bytes, label: str, *, unattended: bool = False) -> bytes:
        return self._create(tag, label, biometry=not unattended)

    def copy_public_key(self, tag: bytes) -> bytes:
        sec = self._security()
        private_key = _lookup_private_key(sec, tag)
        public_key = sec.SecKeyCopyPublicKey(private_key)
        return _export_public_key(sec, public_key)

    def delete_key(self, tag: bytes) -> None:
        sec = self._security()
        status = sec.SecItemDelete(_keychain_query(sec, tag))
        # errSecItemNotFound is success — delete is contractually idempotent.
        if status not in (errSecSuccess, errSecItemNotFound):
            raise _OpsError(status, "OSStatus", "SecItemDelete failed")

    def key_exchange(self, tag: bytes, peer_pub: bytes) -> bytes:
        sec = self._security()
        private_key = _lookup_private_key(sec, tag)
        return _ecdh(sec, private_key, peer_pub)

    def probe(self) -> None:
        """Generate a throwaway ``.privateKeyUsage``-only key and delete it.

        Used by :func:`._seckey_backend.probe_capability`. A failure in
        ``_create`` raises — that *is* the capability signal. A failure in
        the cleanup ``delete_key`` is swallowed: the key generated
        successfully (all the probe proves), so a delete hiccup must not
        flip ``is_secure_enclave_available`` to ``False``. The leftover is
        a random-tagged ``.privateKeyUsage``-only throwaway; re-probes
        never collide because each draws a fresh ``os.urandom`` suffix.
        """
        tag = _PROBE_TAG_PREFIX + os.urandom(8)
        self._create(tag, "Mordred capability probe", biometry=False)
        with contextlib.suppress(_OpsError):
            self.delete_key(tag)


def _nserror_code(err: Any) -> int:
    """Extract the integer code from a pyobjc ``NSError`` (or ``None``)."""
    if err is None:
        return errSecAuthFailed
    return int(err.code())


def _nserror_domain(err: Any) -> str:
    """Extract the domain string from a pyobjc ``NSError`` (or ``None``)."""
    if err is None:
        return "OSStatus"
    return str(err.domain())


def _export_public_key(sec: Any, public_key: Any) -> bytes:
    """``SecKeyCopyExternalRepresentation`` → SEC1 uncompressed bytes."""
    data, err = sec.SecKeyCopyExternalRepresentation(public_key, None)
    if data is None:
        raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCopyExternalRepresentation failed")
    return bytes(data)


def _ecdh(sec: Any, private_key: Any, peer_pub: bytes, *, variant: str = "") -> bytes:
    """Shared ``SecKeyCreateWithData`` + ``SecKeyCopyKeyExchangeResult`` body.

    :class:`_PyobjcSecKeyOps.key_exchange` (Secure-Enclave-backed keys) and
    :class:`_SoftwareFallbackOps.key_exchange` (software-backed keys) were
    byte-for-byte identical except for how the private-key ref was looked
    up (``_lookup_private_key`` vs ``_sw_lookup_private_key``). Taking the
    ALREADY-RESOLVED ``private_key`` ref here (rather than a ``tag`` +
    lookup function) lets both callers share this body while keeping their
    distinct lookup call sites.

    ``variant`` is appended to the final error message only, so the two
    callers keep their pre-existing, distinct diagnostic text
    (``"SecKeyCopyKeyExchangeResult failed"`` vs
    ``"SecKeyCopyKeyExchangeResult (software) failed"``) — behavior is
    otherwise identical between the two call sites.
    """
    peer_attrs = {
        sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
        sec.kSecAttrKeyClass: sec.kSecAttrKeyClassPublic,
    }
    peer_key, err = sec.SecKeyCreateWithData(peer_pub, peer_attrs, None)
    if peer_key is None:
        # peer_pub is already SEC1-validated by wrap._parse_header, so
        # this is a genuine native fault rather than a malformed point.
        raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCreateWithData(peer) failed")
    shared, err = sec.SecKeyCopyKeyExchangeResult(
        private_key,
        sec.kSecKeyAlgorithmECDHKeyExchangeStandard,
        peer_key,
        {},
        None,
    )
    if shared is None:
        raise _OpsError(_nserror_code(err), _nserror_domain(err), f"SecKeyCopyKeyExchangeResult{variant} failed")
    return bytes(shared)


def _keychain_query(sec: Any, tag: bytes) -> dict[Any, Any]:
    """Keychain match dict for the Enclave private key tagged ``tag``.

    Pins ``kSecAttrKeyClassPrivate`` + the Secure-Enclave token so a
    same-tag *software* key can never be matched and used without the
    Enclave prompt (codex review BLOCKER).

    Phase 4: queries target the legacy macOS Keychain (no
    ``kSecUseDataProtectionKeychain=True``) to match the write side in
    ``_PyobjcSecKeyOps._create``. The Data Protection Keychain requires
    the ``keychain-access-groups`` entitlement, which an unsigned local
    Python interpreter cannot carry. The codex-review HIGH invariant
    (every ``SecItem*`` op targets the same keychain) is still satisfied
    — uniformly via the legacy keychain instead of uniformly via DPK.
    """
    return {
        sec.kSecClass: sec.kSecClassKey,
        sec.kSecAttrApplicationTag: tag,
        sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
        sec.kSecAttrKeyClass: sec.kSecAttrKeyClassPrivate,
        sec.kSecAttrTokenID: sec.kSecAttrTokenIDSecureEnclave,
    }


def _lookup_private_key(sec: Any, tag: bytes) -> Any:
    """``SecItemCopyMatching`` for the Enclave private key ref by ``tag``.

    Raises :class:`_OpsError` (``errSecItemNotFound`` when absent). The
    ref is consumed immediately by the caller — never stored.
    """
    query = _keychain_query(sec, tag)
    query[sec.kSecReturnRef] = True
    status, ref = sec.SecItemCopyMatching(query, None)
    if status != errSecSuccess or ref is None:
        raise _OpsError(status, "OSStatus", "SecItemCopyMatching failed")
    return ref


def _sw_keychain_query(sec: Any, tag: bytes) -> dict[Any, Any]:
    """Keychain match dict for software-backed P-256 keys tagged ``tag``.

    Unlike :func:`_keychain_query` this does NOT pin ``kSecAttrTokenIDSecureEnclave``
    — software keys carry no token ID. The ``_SW_TAG_PREFIX`` in ``tag``
    is the sole distinguisher from SE keys (codex-review BLOCKER: mixing
    tag prefixes would allow a software key to substitute for an SE key).
    """
    return {
        sec.kSecClass: sec.kSecClassKey,
        sec.kSecAttrApplicationTag: tag,
        sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
        sec.kSecAttrKeyClass: sec.kSecAttrKeyClassPrivate,
    }


def _sw_lookup_private_key(sec: Any, tag: bytes) -> Any:
    """``SecItemCopyMatching`` for the software private key ref by ``tag``."""
    query = _sw_keychain_query(sec, tag)
    query[sec.kSecReturnRef] = True
    status, ref = sec.SecItemCopyMatching(query, None)
    if status != errSecSuccess or ref is None:
        raise _OpsError(status, "OSStatus", "SecItemCopyMatching (software) failed")
    return ref


# ---------------------------------------------------------------------------
# Software-backed fallback ops (no Secure Enclave required)
# ---------------------------------------------------------------------------


class _SoftwareFallbackOps:
    """Software P-256 fallback when Secure Enclave persistence is blocked.

    Invoked by :class:`_SecKeyBackend` when :class:`_PyobjcSecKeyOps`
    raises ``_OpsError(errSecMissingEntitlement)`` — the sign that the
    Python process cannot persist Secure Enclave keys in the Keychain
    (unsigned processes on macOS 15+ trigger this restriction).

    Keys are stored as ordinary software P-256 items in the login Keychain
    under ``_SW_TAG_PREFIX`` tags. ECDH runs in software with no biometric
    prompt. The private key is protected by macOS Keychain access control
    (user session) but is NOT hardware-backed.

    Callers must pass tags drawn from ``_sw_application_tag(key_id)``
    (``_SW_TAG_PREFIX`` namespace) — ``_SecKeyBackend`` handles this.
    The software bridge bug (pyobjc raises ``KeyError`` for SE token keys)
    does NOT affect this class because ``kSecAttrTokenIDSecureEnclave`` is
    absent from the attrs dict.
    """

    def _security(self) -> Any:
        return native._lazy_import_security()

    def create_keypair(self, tag: bytes, label: str, *, unattended: bool = False) -> bytes:
        """Generate a software P-256 keypair and persist it to the login Keychain.

        ``unattended`` is accepted for Protocol parity but ignored: software
        keys carry no biometric access control and never prompt, so the flag
        has no effect here.
        """
        sec = self._security()
        key, err = sec.SecKeyCreateRandomKey(
            {
                sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
                sec.kSecAttrKeySizeInBits: 256,
                sec.kSecPrivateKeyAttrs: {
                    sec.kSecAttrIsPermanent: True,
                    sec.kSecAttrApplicationTag: tag,
                    sec.kSecAttrLabel: label,
                    # Security review H2: pin device-binding. Without an
                    # explicit accessibility class the key defaults to
                    # kSecAttrAccessibleWhenUnlocked, which is iCloud-
                    # syncable and migratable — a "device-bound" wrapping
                    # key that is not actually device-bound.
                    sec.kSecAttrAccessible: sec.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                },
            },
            None,
        )
        if key is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCreateRandomKey (software) failed")
        pub = sec.SecKeyCopyPublicKey(key)
        return _export_public_key(sec, pub)

    def copy_public_key(self, tag: bytes) -> bytes:
        sec = self._security()
        priv = _sw_lookup_private_key(sec, tag)
        pub = sec.SecKeyCopyPublicKey(priv)
        return _export_public_key(sec, pub)

    def delete_key(self, tag: bytes) -> None:
        sec = self._security()
        status = sec.SecItemDelete(_sw_keychain_query(sec, tag))
        if status not in (errSecSuccess, errSecItemNotFound):
            raise _OpsError(status, "OSStatus", "SecItemDelete (software) failed")

    def key_exchange(self, tag: bytes, peer_pub: bytes) -> bytes:
        sec = self._security()
        priv = _sw_lookup_private_key(sec, tag)
        return _ecdh(sec, priv, peer_pub, variant=" (software)")

    def probe(self) -> None:
        """Generate-then-delete a throwaway software key (no biometry flag)."""
        tag = _SW_TAG_PREFIX + b"__probe__." + os.urandom(8)
        sec = self._security()
        key, err = sec.SecKeyCreateRandomKey(
            {
                sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
                sec.kSecAttrKeySizeInBits: 256,
                sec.kSecPrivateKeyAttrs: {
                    sec.kSecAttrIsPermanent: True,
                    sec.kSecAttrApplicationTag: tag,
                    sec.kSecAttrLabel: "Mordred software capability probe",
                    # Security review H2: same device-binding as the
                    # persistent software key, so the throwaway probe key
                    # is never iCloud-syncable either.
                    sec.kSecAttrAccessible: sec.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                },
            },
            None,
        )
        if key is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "software probe: SecKeyCreateRandomKey failed")
        with contextlib.suppress(_OpsError):
            self.delete_key(tag)
