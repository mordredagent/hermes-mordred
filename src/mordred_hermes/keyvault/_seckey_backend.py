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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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

    def create_keypair(self, tag: bytes, label: str) -> bytes:
        """Generate a permanent Secure-Enclave P-256 keypair tagged
        ``tag`` and return the SEC1 uncompressed public key (65 bytes).
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
            # Secure-Enclave keys live in the data-protection keychain;
            # every SecItem* lookup must target the same keychain (see
            # _keychain_query) or it misses the key (codex review HIGH).
            sec.kSecUseDataProtectionKeychain: True,
            sec.kSecPrivateKeyAttrs: private_key_attrs,
        }
        try:
            private_key, err = sec.SecKeyCreateRandomKey(attrs, None)
        except (KeyError, TypeError) as exc:
            # pyobjc-framework-Security bridge regression: when
            # kSecAttrTokenIDSecureEnclave is requested, the C extension
            # raises a bare KeyError for CFString constants ('public' /
            # 'private' / 'applepay') or a TypeError on metadata-signature
            # mismatch instead of returning (None, NSError). Version-
            # independent across pyobjc 10/11/12. Wrap as _OpsError so
            # _SecKeyBackend translates to WrapError and init_keyvault
            # rolls back partial state.
            raise _OpsError(
                -1,
                "pyobjc-bridge",
                f"SecKeyCreateRandomKey bridge error: {exc!r}",
            ) from exc
        if private_key is None:
            raise _OpsError(_nserror_code(err), _nserror_domain(err), "SecKeyCreateRandomKey failed")
        public_key = sec.SecKeyCopyPublicKey(private_key)
        return _export_public_key(sec, public_key)

    def create_keypair(self, tag: bytes, label: str) -> bytes:
        return self._create(tag, label, biometry=True)

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
    Enclave prompt (codex review BLOCKER). ``kSecUseDataProtectionKeychain``
    is required on macOS: Secure-Enclave keys live in the data-protection
    keychain — ``SecItem*`` calls otherwise hit the legacy file-based
    keychain and fail with ``errSecParam`` (codex review HIGH, live-repro).
    """
    return {
        sec.kSecClass: sec.kSecClassKey,
        sec.kSecAttrApplicationTag: tag,
        sec.kSecAttrKeyType: sec.kSecAttrKeyTypeECSECPrimeRandom,
        sec.kSecAttrKeyClass: sec.kSecAttrKeyClassPrivate,
        sec.kSecAttrTokenID: sec.kSecAttrTokenIDSecureEnclave,
        sec.kSecUseDataProtectionKeychain: True,
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


# ---------------------------------------------------------------------------
# NativeBackend implementation
# ---------------------------------------------------------------------------


class _SecKeyBackend:
    """Production :class:`NativeBackend` — Secure-Enclave-backed wrapping keys.

    Holds no pyobjc state: all native I/O is delegated to an injected
    :class:`_SecKeyOps`. ``ops`` defaults to :class:`_PyobjcSecKeyOps`,
    the real bridge; the test suite injects a software-crypto fake so
    the flow + error-translation logic runs on any platform.

    Satisfies the structural :class:`NativeBackend` ``Protocol`` —
    ``isinstance(_SecKeyBackend(), NativeBackend)`` is ``True`` because
    that Protocol is ``@runtime_checkable``.
    """

    def __init__(self, *, ops: _SecKeyOps | None = None) -> None:
        self._ops: _SecKeyOps = ops if ops is not None else _PyobjcSecKeyOps()

    def generate_enclave_key(self, key_id: str) -> bytes:
        try:
            return self._ops.create_keypair(_application_tag(key_id), _keychain_label(key_id))
        except _OpsError as exc:
            if exc.status == errSecDuplicateItem:
                # SPEC.md: an existing tag surfaces as WrapKeyNotFound so
                # callers do not need to know the OSStatus. (The name is
                # historical — "already exists" reuses the not-found
                # class because both mean "cannot generate here".)
                raise WrapKeyNotFound(f"wrapping key {key_id!r} already exists in the Keychain") from exc
            raise WrapError(f"failed to generate Enclave key for {key_id!r}") from exc

    def get_enclave_public_key(self, key_id: str) -> bytes:
        try:
            return self._ops.copy_public_key(_application_tag(key_id))
        except _OpsError as exc:
            if exc.status == errSecItemNotFound:
                raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from exc
            raise WrapError(f"failed to read Enclave public key for {key_id!r}") from exc

    def delete_enclave_key(self, key_id: str) -> None:
        try:
            self._ops.delete_key(_application_tag(key_id))
        except _OpsError as exc:
            # Idempotency is the ops layer's job (errSecItemNotFound is
            # success there); anything reaching here is a genuine fault.
            raise WrapError(f"failed to delete Enclave key for {key_id!r}") from exc

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        try:
            return self._ops.key_exchange(_application_tag(key_id), peer_pub)
        except _OpsError as exc:
            code = _translate_error(exc.status, exc.domain)
            if code == "key_not_found":
                # Missing key is pre-authorization (SPEC.md unwrap step 2):
                # surface WrapKeyNotFound so unwrap_dek emits NO audit entry.
                raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from exc
            # All other codes are prompt-denied / auth failures: hand the
            # frozen string to NativeBackendError so unwrap_dek can emit
            # keyvault.unwrap_denied with a sanitized native_error_code.
            raise NativeBackendError(code) from exc


def probe_capability() -> bool:
    """Generate-then-delete a throwaway Enclave key with no biometry flag.

    Returns ``True`` when the round-trip succeeds. Raises on any failure
    — the caller (:func:`native._probe_secure_enclave_capability`) lets
    :func:`native.is_secure_enclave_available` swallow it into ``False``.
    """
    _PyobjcSecKeyOps().probe()
    return True
