"""Contract: the Keychain/error foundation lives in ``_seckey_errors``.

``_seckey_backend`` had grown past the 800-LOC guideline. The leaf layer —
OSStatus / LAError constants, the Keychain tag-namespace prefixes, the
tag/label helpers, and the platform-neutral failure taxonomy
(``_translate_error`` / ``_OpsError`` / ``OPS_*``) — is extracted into
``_seckey_errors`` so it can be shared without dragging in the pyobjc/Secure
-Enclave machinery. The SE crypto code (``_PyobjcSecKeyOps`` /
``_SoftwareFallbackOps`` / ``_SecKeyBackend``) stays in ``_seckey_backend``.

This pins the post-split surface; the behavioural coverage stays in
``test_keyvault_seckey_backend.py`` (unchanged — those symbols re-expose).
"""

from __future__ import annotations

import pytest

from mordred_hermes.keyvault import _seckey_backend, _seckey_errors

#: Foundation symbols that must live in the new module.
_FOUNDATION = (
    # OSStatus / LAError constants
    "errSecItemNotFound",
    "errSecDuplicateItem",
    "errSecMissingEntitlement",
    "errSecAuthorizationCanceled",
    "_LA_ERROR_DOMAIN",
    # Keychain tag namespace
    "_TAG_PREFIX",
    "_PROBE_TAG_PREFIX",
    "_SW_TAG_PREFIX",
    # tag/label helpers
    "_resolve_unattended",
    "_application_tag",
    "_keychain_label",
    "_sw_application_tag",
    # neutral failure taxonomy
    "_translate_error",
    "_OpsError",
    "OPS_NOT_FOUND",
    "OPS_EXISTS",
    "OPS_UNAVAILABLE",
    "OPS_AUTH_DENIED",
    "_OPS_REASONS",
)

#: Foundation symbols the SE backend still uses internally, so it must keep
#: re-exposing the SAME object (back-compat for existing importers).
_REEXPOSED = (
    "_OpsError",
    "_translate_error",
    "_application_tag",
    "_keychain_label",
    "_sw_application_tag",
    "_resolve_unattended",
    "errSecItemNotFound",
    "errSecMissingEntitlement",
    "OPS_NOT_FOUND",
    "OPS_EXISTS",
)


@pytest.mark.parametrize("name", _FOUNDATION)
def test_seckey_errors_exposes_foundation(name: str) -> None:
    assert hasattr(_seckey_errors, name), f"_seckey_errors must expose {name}"


@pytest.mark.parametrize("name", _REEXPOSED)
def test_backend_reexposes_same_object(name: str) -> None:
    # Existing importers do `from ._seckey_backend import _OpsError` etc.; after
    # the split the backend must still surface the SAME object it now imports.
    assert getattr(_seckey_backend, name) is getattr(_seckey_errors, name)


def test_translate_error_round_trips_through_new_module() -> None:
    # Smoke: the moved taxonomy behaves identically (neutral reason path).
    assert _seckey_errors._translate_error(0, "OSStatus", reason=_seckey_errors.OPS_NOT_FOUND) == "key_not_found"
    assert _seckey_errors._translate_error(_seckey_errors.errSecItemNotFound, "OSStatus") == "key_not_found"
