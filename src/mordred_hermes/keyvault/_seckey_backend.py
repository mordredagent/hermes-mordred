"""Production ``NativeBackend`` — Secure-Enclave wrapping keys with a software P-256 fallback.

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

Backend selection (see :func:`_default_ops`) — the in-process pyobjc ops
below are NOT the primary hardware path. When the ad-hoc-signed
``mordred-hermes-sekey`` helper is installed it owns real Secure-Enclave
keys via CryptoKit (``SecureEnclave.P256``, storing the key's
``dataRepresentation`` as a file — no Keychain, so it sidesteps the
``keychain-access-groups`` entitlement an unsigned Python cannot carry; see
:mod:`._seckey_helper` and ``native/sekey-helper/``).
:class:`_PyobjcSecKeyOps` is only the fallback used when that helper is
absent, and it persists a *real* Enclave key solely on an entitled
interpreter; on an ordinary unsigned Python every SE write fails
``errSecMissingEntitlement`` (-34018) and :class:`_SecKeyBackend`
transparently degrades to a software P-256 key (:class:`_SoftwareFallbackOps`).
Effective hierarchy: signed helper → in-process pyobjc SE (entitled only) →
software P-256. The pyobjc path is retained — rather than deleted in favour
of helper-or-software — so an entitled embedded interpreter keeps an
in-process SE option (decision recorded 2026-06-03).

The pyobjc bridge is reached exclusively through
:func:`mordred_hermes.keyvault.native._lazy_import_security`, so this
module imports cleanly on Linux / Windows just like ``native.py``.
"""

from __future__ import annotations

import contextlib
import enum
import os
import sys
from typing import Any, Final, Protocol

from . import native
from ._exceptions import WrapError, WrapKeyAlreadyExists, WrapKeyNotFound, WrapNativeUnavailable

# The Keychain/error foundation (constants, tag/label helpers, neutral failure
# taxonomy) lives in ``_seckey_errors`` (leaf layer). Re-imported here for use by
# the SE ops + backend below; they also stay importable as ``_seckey_backend``
# attributes for back-compat (existing callers import ``_OpsError`` etc. here).
from ._seckey_errors import (
    _PROBE_TAG_PREFIX,
    _SW_TAG_PREFIX,
    OPS_EXISTS,
    OPS_NOT_FOUND,
    _application_tag,
    _keychain_label,
    _OpsError,
    _resolve_unattended,
    _sw_application_tag,
    _translate_error,
    errSecAuthFailed,
    errSecDuplicateItem,
    errSecItemNotFound,
    errSecMissingEntitlement,
    errSecSuccess,
)
from .wrap import NativeBackendError

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
    helper is absent (see :func:`_default_ops` and the module "Backend
    selection" note): it persists a real Secure-Enclave key only on an
    *entitled* interpreter, otherwise :class:`_SecKeyBackend` degrades to
    software P-256 on ``errSecMissingEntitlement``. Exercised only by the
    live integration test. Every method resolves the pyobjc ``Security``
    module lazily via :func:`native._lazy_import_security`, so importing this
    class costs nothing on a non-macOS host.
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
    """Pick the primary hardware ops for this platform, or fail closed.

    - **macOS**: a separately Developer-ID- (or ad-hoc-) signed
      ``mordred-hermes-sekey`` CLI when installed (the real Secure-Enclave
      path via CryptoKit); otherwise the in-process pyobjc bridge, which
      itself degrades to software P-256 on ``errSecMissingEntitlement``.
    - **Linux**: the ``mordred-hermes-tpmkey`` TPM 2.0 helper when
      installed; otherwise :class:`WrapNativeUnavailable`. There is no
      software floor off macOS (codex review HIGH) — a host without a
      usable TPM fails closed rather than silently downgrading to a
      non-hardware key.
    - **Windows**: the ``mordred-hermes-winkey`` CNG helper (TPM-backed via
      the Platform Crypto Provider) when installed; otherwise
      :class:`WrapNativeUnavailable` — same fail-closed contract as Linux.
    - **Other platforms**: not yet supported.

    The import is function-local so importing ``_seckey_backend`` does not pull
    in ``_seckey_helper`` (and its subprocess machinery) at module load. Both
    now source the shared failure taxonomy from the leaf ``_seckey_errors``
    module, so there is no load-time cycle between them either way.
    """
    from . import _seckey_helper

    if sys.platform == "darwin":
        binary = _seckey_helper._find_helper()
        if binary is not None:
            return _seckey_helper._HelperSecKeyOps(binary)
        return _PyobjcSecKeyOps()

    if sys.platform == "linux":
        binary = _seckey_helper.find_tpmkey_helper()
        if binary is not None:
            return _seckey_helper._HelperSecKeyOps(binary)
        raise WrapNativeUnavailable(
            "Linux keyvault requires the mordred-hermes-tpmkey TPM 2.0 helper; "
            "none found (set MORDRED_TPMKEY_HELPER or install it). See v2-OS2."
        )

    if sys.platform == "win32":
        binary = _seckey_helper.find_winkey_helper()
        if binary is not None:
            return _seckey_helper._HelperSecKeyOps(binary)
        raise WrapNativeUnavailable(
            "Windows keyvault requires the mordred-hermes-winkey CNG helper; "
            "none found (set MORDRED_WINKEY_HELPER or install it). See v2-OS2."
        )

    raise WrapNativeUnavailable(f"hardware keyvault backend not available on platform {sys.platform!r} (v2-OS2).")


def _default_sw_ops() -> _SecKeyOps | None:
    """The software-fallback namespace partner for the primary ops.

    Only macOS has one: :class:`_SoftwareFallbackOps` persists a software
    P-256 key in the login Keychain — the degradation path when an unsigned
    interpreter cannot persist a Secure-Enclave key. Off macOS there is no
    software namespace; returning ``None`` makes :class:`_SecKeyBackend` fail
    closed (a missing key is :class:`WrapKeyNotFound`, never a
    ``Security.framework`` call that would not even import). codex review
    HIGH: do not route Linux through :class:`_SoftwareFallbackOps`.
    """
    if sys.platform == "darwin":
        return _SoftwareFallbackOps()
    return None


def _is_reason(exc: _OpsError, reason: str, *statuses: int) -> bool:
    """Whether ``exc`` denotes ``reason``.

    A reason-carrying error (non-macOS helper) is judged purely by its
    neutral :attr:`_OpsError.reason`; a legacy error (``reason is None`` —
    macOS pyobjc / ``Security.framework``) is judged by its numeric
    ``OSStatus``. The two never mix, so the macOS dispatch is unchanged.
    """
    if exc.reason is not None:
        return exc.reason == reason
    return exc.status in statuses


class _UnsetSwOps(enum.Enum):
    """Sentinel: ``sw_ops`` was not passed → derive the per-platform default.

    A distinct type (not ``None``) so that an explicit ``sw_ops=None`` —
    "no software namespace, fail closed" — is distinguishable from "caller
    did not specify" — "use :func:`_default_sw_ops`".
    """

    SENTINEL = "sentinel"


_DEFAULT_SW_OPS: Final = _UnsetSwOps.SENTINEL


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

    The ``_sw_ops`` (software namespace) is reached not only on
    ``errSecMissingEntitlement`` but also on ``errSecItemNotFound`` (a key may
    live in the software namespace) and on every delete. It is injectable via
    ``sw_ops=`` so a test can exercise the dual-namespace flow with software
    fakes — without it, the real :class:`_SoftwareFallbackOps` reaches
    ``native._security`` and the flow can only run on macOS.

    ``_sw_ops`` may be ``None`` — there is no software namespace off macOS
    (see :func:`_default_sw_ops`). When ``None`` the backend **fails closed**:
    a missing key surfaces as :class:`WrapKeyNotFound` directly, and no
    ``Security.framework`` call is ever attempted. Not passing ``sw_ops``
    derives the per-platform default; passing ``sw_ops=None`` explicitly
    forces fail-closed.

    Satisfies the structural :class:`NativeBackend` ``Protocol`` —
    ``isinstance(_SecKeyBackend(), NativeBackend)`` is ``True`` because
    that Protocol is ``@runtime_checkable``.
    """

    def __init__(
        self,
        *,
        ops: _SecKeyOps | None = None,
        sw_ops: _SecKeyOps | None | _UnsetSwOps = _DEFAULT_SW_OPS,
    ) -> None:
        self._ops: _SecKeyOps = ops if ops is not None else _default_ops()
        self._sw_ops: _SecKeyOps | None = _default_sw_ops() if isinstance(sw_ops, _UnsetSwOps) else sw_ops

    # ----- generate -----

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        resolved = _resolve_unattended(unattended)
        try:
            return self._ops.create_keypair(_application_tag(key_id), _keychain_label(key_id), unattended=resolved)
        except _OpsError as exc:
            if _is_reason(exc, OPS_EXISTS, errSecDuplicateItem):
                # An existing tag surfaces as WrapKeyAlreadyExists — still a
                # WrapKeyNotFound subclass, so callers written against the
                # historical mapping ("already exists" reused the not-found
                # class) keep catching it without knowing the OSStatus.
                raise WrapKeyAlreadyExists(f"wrapping key {key_id!r} already exists in the Keychain") from exc
            if self._sw_ops is not None and exc.reason is None and exc.status == errSecMissingEntitlement:
                # macOS only: unsigned Python cannot persist SE keys — fall
                # back to a software P-256 key. A reason-carrying helper
                # (TPM / CNG) never raises this, so the branch is inert
                # off macOS.
                return self._generate_software(key_id, unattended=resolved)
            raise WrapError(f"failed to generate Enclave key for {key_id!r}") from exc

    def _generate_software(self, key_id: str, *, unattended: bool = False) -> bytes:
        # Only reached on the macOS entitlement-fallback path (caller guards
        # ``sw_ops is not None``).
        assert self._sw_ops is not None
        try:
            return self._sw_ops.create_keypair(
                _sw_application_tag(key_id), _keychain_label(key_id), unattended=unattended
            )
        except _OpsError as exc:
            if _is_reason(exc, OPS_EXISTS, errSecDuplicateItem):
                raise WrapKeyAlreadyExists(f"wrapping key {key_id!r} already exists in the Keychain") from exc
            raise WrapError(f"failed to generate wrapping key for {key_id!r}") from exc

    # ----- get public key -----

    def get_enclave_public_key(self, key_id: str) -> bytes:
        try:
            return self._ops.copy_public_key(_application_tag(key_id))
        except _OpsError as exc:
            if _is_reason(exc, OPS_NOT_FOUND, errSecItemNotFound):
                if self._sw_ops is None:
                    # Fail closed: no software namespace off macOS.
                    raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from exc
                # Not in SE namespace — try software namespace.
                return self._get_software_public_key(key_id, exc)
            raise WrapError(f"failed to read Enclave public key for {key_id!r}") from exc

    def _get_software_public_key(self, key_id: str, se_exc: _OpsError) -> bytes:
        # Only reached on the macOS dual-namespace path: the caller already
        # returned/raised when ``sw_ops is None``, so it is non-None here.
        assert self._sw_ops is not None
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
        # That suppression is macOS-only (reason is None); any reason-carrying
        # helper error propagates.
        try:
            self._ops.delete_key(_application_tag(key_id))
        except _OpsError as exc:
            if not (exc.reason is None and exc.status == errSecMissingEntitlement):
                raise WrapError(f"failed to delete Enclave key for {key_id!r}") from exc

        # No software namespace off macOS — nothing more to delete.
        if self._sw_ops is None:
            return

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
            if _is_reason(exc, OPS_NOT_FOUND, errSecItemNotFound):
                if self._sw_ops is None:
                    # Fail closed: no software namespace off macOS.
                    raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from exc
                # Key not in SE namespace — try software namespace.
                return self._ecdh_software(key_id, peer_pub, exc)
            code = _translate_error(exc.status, exc.domain, exc.reason)
            if code == "key_not_found":
                raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from exc
            raise NativeBackendError(code) from exc

    def _ecdh_software(self, key_id: str, peer_pub: bytes, se_exc: _OpsError) -> bytes:
        # Only reached on the macOS dual-namespace path: the caller already
        # raised when ``sw_ops is None``, so ``_sw_ops`` is non-None here.
        assert self._sw_ops is not None
        try:
            return self._sw_ops.key_exchange(_sw_application_tag(key_id), peer_pub)
        except _OpsError as exc:
            code = _translate_error(exc.status, exc.domain, exc.reason)
            if code == "key_not_found":
                # Neither SE nor SW namespace has this key.
                raise WrapKeyNotFound(f"no wrapping key for {key_id!r} in the Keychain") from se_exc
            raise NativeBackendError(code) from exc


def probe_capability() -> bool:
    """Generate-then-delete a throwaway key with no biometry flag.

    Platform-aware, mirroring :func:`_default_ops`:

    - **macOS**: probe through the signed ``mordred-hermes-sekey`` helper
      when installed (the real SE path); otherwise in-process pyobjc
      Secure Enclave, degrading to a software P-256 key in the login
      Keychain on ``errSecMissingEntitlement`` (-34018 — unsigned Python on
      macOS 15+).
    - **Linux**: probe through the ``mordred-hermes-tpmkey`` TPM 2.0 helper
      when installed; otherwise :class:`WrapNativeUnavailable` (no software
      floor off macOS).
    - **Windows**: probe through the ``mordred-hermes-winkey`` CNG helper
      when installed; otherwise :class:`WrapNativeUnavailable` (same
      fail-closed contract as Linux).

    Returns ``True`` when a round-trip succeeds. Raises on any other failure
    so :func:`native.is_secure_enclave_available` can swallow it into
    ``False``.
    """
    from . import _seckey_helper

    if sys.platform == "linux":
        binary = _seckey_helper.find_tpmkey_helper()
        if binary is not None:
            _seckey_helper._HelperSecKeyOps(binary).probe()
            return True
        raise WrapNativeUnavailable("Linux keyvault requires the mordred-hermes-tpmkey TPM 2.0 helper; none found.")

    if sys.platform == "win32":
        binary = _seckey_helper.find_winkey_helper()
        if binary is not None:
            _seckey_helper._HelperSecKeyOps(binary).probe()
            return True
        raise WrapNativeUnavailable("Windows keyvault requires the mordred-hermes-winkey CNG helper; none found.")

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
