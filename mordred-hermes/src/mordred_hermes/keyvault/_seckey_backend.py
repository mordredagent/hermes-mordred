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
   ``Security.framework`` type ever crosses this boundary. This layer
   (the Protocol plus the :class:`_PyobjcSecKeyOps` /
   :class:`_SoftwareFallbackOps` implementations) lives in
   :mod:`._seckey_ops`; it is re-imported and re-exported here so existing
   callers that reference ``_seckey_backend._PyobjcSecKeyOps`` etc. keep
   working (see ``__all__``).
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
in :mod:`._seckey_ops` are NOT the primary hardware path. When the
ad-hoc-signed ``mordred-hermes-sekey`` helper is installed it owns real
Secure-Enclave keys via CryptoKit (``SecureEnclave.P256``, storing the
key's ``dataRepresentation`` as a file — no Keychain, so it sidesteps the
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
"""

from __future__ import annotations

import enum
import sys
from typing import Final

from ._exceptions import WrapError, WrapKeyAlreadyExists, WrapKeyNotFound, WrapNativeUnavailable

# The Keychain/error foundation (constants, tag/label helpers, neutral failure
# taxonomy) lives in ``_seckey_errors`` (leaf layer); the pyobjc-touching ops
# layer (the ``_SecKeyOps`` Protocol + ``_PyobjcSecKeyOps`` /
# ``_SoftwareFallbackOps`` implementations) lives in ``_seckey_ops``. Both are
# re-imported here for use by the backend below, and stay importable as
# ``_seckey_backend`` attributes for back-compat: existing callers import the
# error taxonomy (``_OpsError`` / ``errSec*`` / tag prefixes) and the ops
# (``_PyobjcSecKeyOps`` / ``_keychain_query``) from this module. Several are not
# used here directly any more — they are re-exported solely to keep the public
# attribute surface of ``_seckey_backend`` identical to before the ops split
# (listed in ``__all__`` so ruff treats them as the intended re-exports).
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
from ._seckey_ops import (
    _keychain_query,
    _PyobjcSecKeyOps,
    _SecKeyOps,
    _SoftwareFallbackOps,
)
from .wrap import NativeBackendError

__all__ = [
    "_PROBE_TAG_PREFIX",
    "_SW_TAG_PREFIX",
    "_OpsError",
    "_PyobjcSecKeyOps",
    "_SecKeyBackend",
    "_SecKeyOps",
    "_SoftwareFallbackOps",
    "_default_ops",
    "_default_sw_ops",
    "_is_reason",
    "_keychain_query",
    "errSecAuthFailed",
    "errSecDuplicateItem",
    "errSecItemNotFound",
    "errSecMissingEntitlement",
    "errSecSuccess",
    "probe_capability",
]


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
