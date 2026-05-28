"""Production ``NativeBackend`` — Secure-Enclave keypairs via pyobjc.

Phase 4 PR4 (production backend). :class:`_SecKeyBackend` is the real
implementation of the :class:`mordred_hermes.keyvault.wrap.NativeBackend`
``Protocol`` frozen in SPEC.md §Wrap wire format & algorithm. Until this
module landed, only the software ``FakeBackend`` (in the test suite)
satisfied the Protocol, which left ``hermes mordred keyvault init`` /
``recover`` and ``audit decrypt`` raising ``NotImplementedError``.

Design — two layers (mirrors ``native.py``'s narrow-boundary convention):

1. :class:`_SecKeyOps` ``Protocol`` — the *narrowest possible*
   pyobjc-touching surface: create / lookup-public / delete / ECDH.
   Each method returns plain ``bytes`` or raises :class:`_OpsError`
   carrying a translated ``OSStatus`` / ``LAError`` code. No
   ``Security.framework`` type ever crosses this boundary.
2. :class:`_SecKeyBackend` — the flow + error-translation logic. It
   builds the Keychain ``kSecAttrApplicationTag``, maps :class:`_OpsError`
   to the frozen :class:`WrapError` / :class:`NativeBackendError`
   taxonomy, and is exercised cross-platform by injecting a fake
   ``_SecKeyOps``. The production ops (:class:`_PyobjcSecKeyOps`) is
   covered only by the live integration test
   (``tests/integration/test_keyvault_macos.py``, gated by
   ``MORDRED_KEYVAULT_LIVE=1``) — CI cannot satisfy a biometric prompt
   (SPEC.md review HIGH-4).

The pyobjc bridge is reached exclusively through
:func:`mordred_hermes.keyvault.native._lazy_import_security`, so this
module imports cleanly on Linux / Windows just like ``native.py``.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any, Protocol

from . import native
from ._exceptions import WrapError, WrapKeyNotFound

# ``_key_id_hash`` is imported deliberately: the Keychain tag MUST use the
# exact SHA-256 prefix that ``wrap`` binds into the blob's ``key_id_hash``
# field. Reusing the canonical helper — rather than re-deriving the hash —
# keeps the on-disk blob and the Keychain lookup in lockstep.
from .wrap import NativeBackendError, NativeErrorCode, _key_id_hash

# ---------------------------------------------------------------------------
# OSStatus / LAError constants (Security.framework + LocalAuthentication)
# ---------------------------------------------------------------------------
#
# These ints are stable ABI — Apple has not changed them across macOS
# releases. They are mirrored here so the translation logic is testable
# without pyobjc (the live backend never compares against these names,
# it compares against the raw ints surfaced by NSError.code()).

errSecSuccess = 0
errSecItemNotFound = -25300
errSecDuplicateItem = -25299
errSecAuthFailed = -25293
errSecUserCanceled = -128
errSecInteractionNotAllowed = -25308
errSecMissingEntitlement = -34018
# Authorization Services cancel — SPEC.md §Wrap "unwrap_dek" step 4 lists
# it in the prompt-denial set. Distinct from errSecUserCanceled (-128).
errSecAuthorizationCanceled = -60006

# LocalAuthentication LAError domain ("com.apple.LocalAuthentication").
# SecKeyCopyKeyExchangeResult surfaces biometric-prompt failures in this
# domain, not the OSStatus domain — the translation table handles both.
_LA_ERROR_DOMAIN = "com.apple.LocalAuthentication"
LAErrorAuthenticationFailed = -1
LAErrorUserCancel = -2
LAErrorUserFallback = -3
LAErrorSystemCancel = -4
LAErrorPasscodeNotSet = -5
LAErrorBiometryNotAvailable = -6
LAErrorBiometryNotEnrolled = -7
LAErrorBiometryLockout = -8

# Keychain tag namespace — SPEC.md §Wrap wire format "Access-control
# attributes": kSecAttrApplicationTag = b"mordred-hermes.wrap." + key_id_hash.
_TAG_PREFIX = b"mordred-hermes.wrap."

# Reserved tag suffix for the capability probe (native._probe_*). A
# random suffix is appended per probe so concurrent probes never collide
# on errSecDuplicateItem.
_PROBE_TAG_PREFIX = _TAG_PREFIX + b"__probe__."

# Software-fallback tag prefix — used when Secure Enclave persistence is
# blocked by errSecMissingEntitlement (-34018). Distinct prefix so SE keys
# and software-backed keys never collide in the Keychain and are always
# looked up independently (codex-review BLOCKER: same tag + different token
# would let a software key silently substitute for an SE key).
_SW_TAG_PREFIX = b"mordred-hermes.wrsw."


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Env var that sets the default authorization policy for newly generated
# wrapping keys when a caller does not pass ``unattended`` explicitly.
# ``MORDRED_SEKEY_UNATTENDED=1`` makes new keys ``.privateKeyUsage``-only
# (no Touch ID / passcode prompt on ECDH); anything else keeps the safe
# interactive default. Per-call ``unattended=`` always wins over the env.
_UNATTENDED_ENV = "MORDRED_SEKEY_UNATTENDED"


def _resolve_unattended(unattended: bool | None) -> bool:
    """Resolve the effective unattended policy for key generation.

    Explicit ``True`` / ``False`` is authoritative. ``None`` (caller did
    not specify) falls back to the ``MORDRED_SEKEY_UNATTENDED`` env var,
    defaulting to interactive (``False``) when unset.
    """
    if unattended is not None:
        return unattended
    return os.environ.get(_UNATTENDED_ENV, "") == "1"


def _application_tag(key_id: str) -> bytes:
    """Keychain ``kSecAttrApplicationTag`` for ``key_id``.

    Uses the 16-byte ``SHA-256(key_id)`` prefix (the same value bound
    into the wrap-blob ``key_id_hash`` field) so the cleartext ``key_id``
    never reaches the Keychain — mirrors POLICY.md #19.
    """
    return _TAG_PREFIX + _key_id_hash(key_id)


def _keychain_label(key_id: str) -> str:
    """Human-readable ``kSecAttrLabel`` shown in Keychain Access.app."""
    return "Mordred wrapping key " + _key_id_hash(key_id)[:8].hex()


def _sw_application_tag(key_id: str) -> bytes:
    """Software-fallback Keychain tag for ``key_id``.

    Uses ``_SW_TAG_PREFIX`` so software-backed keys are never confused with
    SE-backed keys at lookup time — the prefix is the distinguishing signal.
    """
    return _SW_TAG_PREFIX + _key_id_hash(key_id)


# Unknown native codes collapse to ``auth_failed`` — the conservative
# choice: it tells the caller "the Enclave refused" without claiming a
# more specific cause than we can prove.
_DEFAULT_ERROR_CODE: NativeErrorCode = "auth_failed"

_LA_ERROR_TABLE: dict[int, NativeErrorCode] = {
    LAErrorUserCancel: "user_cancelled",
    LAErrorUserFallback: "user_cancelled",
    LAErrorSystemCancel: "user_cancelled",
    LAErrorAuthenticationFailed: "auth_failed",
    LAErrorBiometryNotAvailable: "auth_failed",
    LAErrorBiometryNotEnrolled: "auth_failed",
    LAErrorPasscodeNotSet: "passcode_not_set",
    LAErrorBiometryLockout: "biometry_lockout",
}

_OSSTATUS_ERROR_TABLE: dict[int, NativeErrorCode] = {
    errSecUserCanceled: "user_cancelled",
    errSecAuthorizationCanceled: "user_cancelled",
    errSecAuthFailed: "auth_failed",
    errSecItemNotFound: "key_not_found",
    errSecInteractionNotAllowed: "biometry_lockout",
}


def _translate_error(status: int, domain: str) -> NativeErrorCode:
    """Translate a raw ``OSStatus`` / ``LAError`` int to a frozen code.

    The frozen set is :data:`mordred_hermes.keyvault.wrap.NativeErrorCode`.
    Raw ints MUST NOT cross the audit boundary (SPEC.md / POLICY.md #20:
    they carry biometric-attempt-count state), so every native failure
    is collapsed here into one of five closed strings.
    """
    table = _LA_ERROR_TABLE if domain == _LA_ERROR_DOMAIN else _OSSTATUS_ERROR_TABLE
    return table.get(status, _DEFAULT_ERROR_CODE)


class _OpsError(Exception):
    """Raised by :class:`_SecKeyOps` to carry a native failure.

    Holds the raw ``status`` int and ``domain`` string only. The
    translation into the frozen :data:`NativeErrorCode` set happens in
    :class:`_SecKeyBackend` so the ops layer stays a thin pyobjc shim
    with no policy. ``status`` never reaches the audit log.
    """

    def __init__(self, status: int, domain: str = "OSStatus", message: str = "") -> None:
        self.status = status
        self.domain = domain
        super().__init__(message or f"native keychain op failed: domain={domain} status={status}")


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
    """Production :class:`_SecKeyOps` — real ``Security.framework`` calls.

    Exercised only by the live integration test. Every method resolves
    the pyobjc ``Security`` module lazily via
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
            # Phase 4: persist to the legacy macOS Keychain. The Data
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
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCopyKeyExchangeResult failed")
        return bytes(shared)

    def probe(self) -> None:
        """Generate a throwaway ``.privateKeyUsage``-only key and delete it.

        Used by :func:`probe_capability`. A failure in ``_create`` raises
        — that *is* the capability signal. A failure in the cleanup
        ``delete_key`` is swallowed: the key generated successfully (all
        the probe proves), so a delete hiccup must not flip
        ``is_secure_enclave_available`` to ``False``. The leftover is a
        random-tagged ``.privateKeyUsage``-only throwaway; re-probes never
        collide because each draws a fresh ``os.urandom`` suffix.
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
        peer_attrs = {
            sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
            sec.kSecAttrKeyClass: sec.kSecAttrKeyClassPublic,
        }
        peer_key, err = sec.SecKeyCreateWithData(peer_pub, peer_attrs, None)
        if peer_key is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCreateWithData(peer) failed")
        shared, err = sec.SecKeyCopyKeyExchangeResult(
            priv,
            sec.kSecKeyAlgorithmECDHKeyExchangeStandard,
            peer_key,
            {},
            None,
        )
        if shared is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCopyKeyExchangeResult (software) failed")
        return bytes(shared)

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
                },
            },
            None,
        )
        if key is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "software probe: SecKeyCreateRandomKey failed")
        with contextlib.suppress(_OpsError):
            self.delete_key(tag)


# ---------------------------------------------------------------------------
# Ops selection
# ---------------------------------------------------------------------------


def _default_ops() -> _SecKeyOps:
    """Pick the SE ops backend: signed helper if present, else pyobjc.

    A separately Developer-ID-signed ``mordred-hermes-sekey`` CLI can carry
    the ``keychain-access-groups`` entitlement that an unsigned Python
    interpreter cannot, so when it is installed it becomes the real SE path
    (no software fallback needed). When absent we keep the in-process pyobjc
    ops, which itself degrades to software P-256 on ``errSecMissingEntitlement``.

    The import is function-local to keep the ``_seckey_helper`` ↔
    ``_seckey_backend`` dependency one-directional (``_seckey_helper`` imports
    ``_OpsError`` from this module at load time).
    """
    from . import _seckey_helper

    binary = _seckey_helper._find_helper()
    if binary is not None:
        return _seckey_helper._HelperSecKeyOps(binary)
    return _PyobjcSecKeyOps()


# ---------------------------------------------------------------------------
# NativeBackend implementation
# ---------------------------------------------------------------------------


class _SecKeyBackend:
    """Production :class:`NativeBackend` — wrapping keys via Secure Enclave or
    software P-256 fallback.

    Holds no pyobjc state: all native I/O is delegated to an injected
    :class:`_SecKeyOps`. ``ops`` defaults to :class:`_PyobjcSecKeyOps`
    (SE); when that raises ``errSecMissingEntitlement`` (-34018) —
    unsigned Python on macOS 15+ cannot persist SE keys — each method
    retries with :class:`_SoftwareFallbackOps` under the ``_SW_TAG_PREFIX``
    namespace so SE keys and software keys never collide.

    Tests inject a fake ops via ``ops=``; the ``_sw_ops`` is only reached
    on genuine ``errSecMissingEntitlement``, which fake ops never raise.

    Satisfies the structural :class:`NativeBackend` ``Protocol`` —
    ``isinstance(_SecKeyBackend(), NativeBackend)`` is ``True`` because
    that Protocol is ``@runtime_checkable``.
    """

    def __init__(self, *, ops: _SecKeyOps | None = None) -> None:
        self._ops: _SecKeyOps = ops if ops is not None else _default_ops()
        self._sw_ops = _SoftwareFallbackOps()

    # ----- generate -----

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        resolved = _resolve_unattended(unattended)
        try:
            return self._ops.create_keypair(
                _application_tag(key_id), _keychain_label(key_id), unattended=resolved
            )
        except _OpsError as exc:
            if exc.status == errSecDuplicateItem:
                # SPEC.md: an existing tag surfaces as WrapKeyNotFound so
                # callers do not need to know the OSStatus. (The name is
                # historical — "already exists" reuses the not-found
                # class because both mean "cannot generate here".)
                raise WrapKeyNotFound(f"wrapping key {key_id!r} already exists in the Keychain") from exc
            if exc.status == errSecMissingEntitlement:
                # Unsigned Python process — fall back to software P-256 key.
                return self._generate_software(key_id, unattended=resolved)
            raise WrapError(f"failed to generate Enclave key for {key_id!r}") from exc

    def _generate_software(self, key_id: str, *, unattended: bool = False) -> bytes:
        try:
            return self._sw_ops.create_keypair(
                _sw_application_tag(key_id), _keychain_label(key_id), unattended=unattended
            )
        except _OpsError as exc:
            if exc.status == errSecDuplicateItem:
                raise WrapKeyNotFound(f"wrapping key {key_id!r} already exists in the Keychain") from exc
            raise WrapError(f"failed to generate wrapping key for {key_id!r}") from exc

    # ----- get public key -----

    def get_enclave_public_key(self, key_id: str) -> bytes:
        try:
            return self._ops.copy_public_key(_application_tag(key_id))
        except _OpsError as exc:
            if exc.status == errSecItemNotFound:
                # Not in SE namespace — try software namespace.
                return self._get_software_public_key(key_id, exc)
            raise WrapError(f"failed to read Enclave public key for {key_id!r}") from exc

    def _get_software_public_key(self, key_id: str, se_exc: _OpsError) -> bytes:
        try:
            return self._sw_ops.copy_public_key(_sw_application_tag(key_id))
        except _OpsError as exc:
            if exc.status == errSecItemNotFound:
                raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from se_exc
            raise WrapError(f"failed to read wrapping key for {key_id!r}") from exc

    # ----- delete -----

    def delete_enclave_key(self, key_id: str) -> None:
        # Attempt SE delete; suppress errSecMissingEntitlement — unsigned
        # Python cannot delete SE items (key was stored under SW prefix).
        try:
            self._ops.delete_key(_application_tag(key_id))
        except _OpsError as exc:
            if exc.status != errSecMissingEntitlement:
                raise WrapError(f"failed to delete Enclave key for {key_id!r}") from exc

        # Always attempt SW delete (idempotent — errSecItemNotFound = success).
        try:
            self._sw_ops.delete_key(_sw_application_tag(key_id))
        except _OpsError as exc:
            raise WrapError(f"failed to delete wrapping key for {key_id!r}") from exc

    # ----- ECDH -----

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        try:
            return self._ops.key_exchange(_application_tag(key_id), peer_pub)
        except _OpsError as exc:
            if exc.status == errSecItemNotFound:
                # Key not in SE namespace — try software namespace.
                return self._ecdh_software(key_id, peer_pub, exc)
            code = _translate_error(exc.status, exc.domain)
            if code == "key_not_found":
                raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from exc
            raise NativeBackendError(code) from exc

    def _ecdh_software(self, key_id: str, peer_pub: bytes, se_exc: _OpsError) -> bytes:
        try:
            return self._sw_ops.key_exchange(_sw_application_tag(key_id), peer_pub)
        except _OpsError as exc:
            code = _translate_error(exc.status, exc.domain)
            if code == "key_not_found":
                # Neither SE nor SW namespace has this key.
                raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from se_exc
            raise NativeBackendError(code) from exc


def probe_capability() -> bool:
    """Generate-then-delete a throwaway key with no biometry flag.

    When the signed ``mordred-hermes-sekey`` helper is installed, probe
    through it — it is the real SE path and a success there proves hardware
    capability. Otherwise try in-process pyobjc Secure Enclave; if the
    process lacks the entitlement to persist SE keys
    (``errSecMissingEntitlement``, -34018 — unsigned Python on macOS 15+),
    fall back to a software P-256 key in the login Keychain. Returns ``True``
    when a round-trip succeeds. Raises on any other failure so
    :func:`native.is_secure_enclave_available` can swallow it into ``False``.
    """
    from . import _seckey_helper

    binary = _seckey_helper._find_helper()
    if binary is not None:
        _seckey_helper._HelperSecKeyOps(binary).probe()
        return True

    try:
        _PyobjcSecKeyOps().probe()
        return True
    except _OpsError as exc:
        if exc.status != errSecMissingEntitlement:
            raise
    # SE probe blocked by entitlement — try software fallback.
    _SoftwareFallbackOps().probe()
    return True
