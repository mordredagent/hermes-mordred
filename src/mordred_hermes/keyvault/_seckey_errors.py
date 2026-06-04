"""Keychain / error foundation for the macOS Secure-Enclave backend.

Extracted from :mod:`_seckey_backend` (the leaf layer): the OSStatus / LAError
constants mirrored from Security.framework + LocalAuthentication, the Keychain
tag-namespace prefixes, the tag/label derivation helpers, and the
platform-neutral failure taxonomy (:func:`_translate_error` / :class:`_OpsError`
/ the ``OPS_*`` reasons). Depends only on :mod:`.wrap` and the stdlib, so it can
be shared by ``_seckey_backend`` (pyobjc / Secure-Enclave) and ``_seckey_helper``
(out-of-process helper) without either pulling in the other's machinery.
"""

from __future__ import annotations

import os
from typing import Final

# ``_key_id_hash`` is imported deliberately: the Keychain tag MUST use the
# exact SHA-256 prefix that ``wrap`` binds into the blob's ``key_id_hash``
# field. Reusing the canonical helper — rather than re-deriving the hash —
# keeps the on-disk blob and the Keychain lookup in lockstep.
from .wrap import NativeErrorCode, _key_id_hash

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

# ---------------------------------------------------------------------------
# Platform-neutral failure taxonomy (v2-OS2 — Linux TPM / Windows CNG)
# ---------------------------------------------------------------------------
#
# A non-macOS backend helper (TPM, CNG) has no ``OSStatus`` ints. Instead of
# inventing fake ``errSec*`` values it reports a neutral ``reason`` alongside
# the failure. When ``_OpsError.reason`` is set, ``_SecKeyBackend`` dispatches
# purely on it and the numeric ``status`` is ignored; when it is ``None`` the
# legacy macOS dispatch on ``errSec*`` runs unchanged. The two worlds never
# mix, so the Secure-Enclave path is byte-for-byte identical to before.

OPS_NOT_FOUND: Final = "NOT_FOUND"
OPS_EXISTS: Final = "EXISTS"
OPS_UNAVAILABLE: Final = "UNAVAILABLE"
OPS_AUTH_DENIED: Final = "AUTH_DENIED"

# Inbound-validation allow-list: a helper-supplied reason outside this set is
# normalised to ``None`` (forward-compatible — an older client just loses the
# neutral shortcut and falls back to the numeric status).
_OPS_REASONS: Final = frozenset({OPS_NOT_FOUND, OPS_EXISTS, OPS_UNAVAILABLE, OPS_AUTH_DENIED})

# Neutral reason → frozen NativeErrorCode. ``OPS_EXISTS`` is intentionally
# absent: "already exists" is handled in ``generate_enclave_key`` before any
# translation, and is not a meaningful ECDH/lookup failure code.
#
# ``OPS_UNAVAILABLE`` deliberately collapses to ``auth_failed`` (the
# conservative default) in Phase 1: the frozen :data:`NativeErrorCode` set
# has no "hardware went away" member, and no helper emits ``UNAVAILABLE``
# yet (the TPM helper does not exist until Phase 2). Adding a dedicated
# ``hardware_unavailable`` code — and routing mid-operation ``UNAVAILABLE``
# to :class:`WrapNativeUnavailable` instead of :class:`NativeBackendError` —
# is a SPEC change tracked for Phase 2, when a real helper can exercise it.
_REASON_ERROR_TABLE: dict[str, NativeErrorCode] = {
    OPS_NOT_FOUND: "key_not_found",
    OPS_AUTH_DENIED: "auth_failed",
    OPS_UNAVAILABLE: "auth_failed",
}


def _translate_error(status: int, domain: str, reason: str | None = None) -> NativeErrorCode:
    """Translate a raw ``OSStatus`` / ``LAError`` int — or a neutral
    ``reason`` — to a frozen code.

    The frozen set is :data:`mordred_hermes.keyvault.wrap.NativeErrorCode`.
    Raw ints MUST NOT cross the audit boundary (SPEC.md / POLICY.md #20:
    they carry biometric-attempt-count state), so every native failure
    is collapsed here into one of five closed strings. A non-macOS helper
    supplies ``reason`` and is dispatched through :data:`_REASON_ERROR_TABLE`,
    ignoring ``status`` entirely.
    """
    if reason is not None:
        return _REASON_ERROR_TABLE.get(reason, _DEFAULT_ERROR_CODE)
    table = _LA_ERROR_TABLE if domain == _LA_ERROR_DOMAIN else _OSSTATUS_ERROR_TABLE
    return table.get(status, _DEFAULT_ERROR_CODE)


class _OpsError(Exception):
    """Raised by :class:`_SecKeyOps` to carry a native failure.

    Holds the raw ``status`` int and ``domain`` string, plus an optional
    platform-neutral ``reason`` (one of :data:`_OPS_REASONS`). macOS pyobjc
    ops leave ``reason=None`` and carry only the ``OSStatus``; a non-macOS
    helper (TPM / CNG) sets ``reason`` so :class:`_SecKeyBackend` can
    dispatch without inventing fake ``errSec*`` ints. The translation into
    the frozen :data:`NativeErrorCode` set happens in
    :class:`_SecKeyBackend` so the ops layer stays a thin shim with no
    policy. Neither ``status`` nor ``reason`` reaches the audit log.
    """

    def __init__(
        self,
        status: int,
        domain: str = "OSStatus",
        message: str = "",
        *,
        reason: str | None = None,
    ) -> None:
        self.status = status
        self.domain = domain
        self.reason = reason
        super().__init__(message or f"native keychain op failed: domain={domain} status={status}")
