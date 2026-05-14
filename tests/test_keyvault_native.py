"""RED tests for Phase 4 PR3 step-A: lazy ``Security.framework`` wrapper.

Per SPEC.md §Wrap wire format & algorithm (Phase 4 PR3 freeze, 2026-05-14):

- ``import mordred_hermes.keyvault.native`` MUST succeed on any platform
  (Linux / Windows / macOS). The pyobjc import is deferred until a
  function that actually needs it is called.
- ``_lazy_import_security()`` returns the Security module on macOS and
  raises :class:`WrapNativeUnavailable` elsewhere (codex review HIGH-3
  follow-up: on macOS without pyobjc, the ImportError is chained so
  callers can distinguish "wrong platform" from "missing extras").
- ``is_secure_enclave_available()`` probes capability via a throwaway
  key-generate-then-delete cycle (codex review MEDIUM-1). It does NOT
  inspect ``platform.machine()``: T2 Intel Macs also have a Secure
  Enclave.

These tests are designed to run cross-platform: every code path that
would call pyobjc is exercised through a ``_FakeSecurity`` injected via
``monkeypatch.setattr(native, "_security_module", fake)``.
"""

from __future__ import annotations

from typing import Any

import pytest


def test_module_import_does_not_raise_on_any_platform() -> None:
    """SPEC.md §Plugin: ``mordred_keyvault`` (Implementation interface +
    Files): ``native.py`` must import cleanly on Linux/Windows so
    ``mordred_hermes.keyvault`` is usable for non-keyvault primitives
    (digest, backup, recovery already landed in PR2). pyobjc must be
    deferred to call time.
    """
    import mordred_hermes.keyvault.native  # noqa: F401


def test_wrap_error_taxonomy_exported() -> None:
    """SPEC.md §Wrap wire format & algorithm "Internal Python surface"
    freezes a 6-class taxonomy. All must be importable from
    ``keyvault._exceptions`` and form a subclass tree rooted at
    :class:`WrapError`."""
    from mordred_hermes.keyvault._exceptions import (
        WrapAuthCancelled,
        WrapError,
        WrapIntegrityError,
        WrapKeyNotFound,
        WrapNativeUnavailable,
        WrapParseError,
    )

    for cls in (
        WrapParseError,
        WrapIntegrityError,
        WrapNativeUnavailable,
        WrapAuthCancelled,
        WrapKeyNotFound,
    ):
        assert issubclass(cls, WrapError), f"{cls.__name__} must inherit from WrapError"
        assert issubclass(cls, Exception), f"{cls.__name__} must inherit from Exception (not BaseException)"


def test_wrap_error_subclasses_are_distinct() -> None:
    """Codex review NIT-1: ``WrapAuthFailed`` (the originally-proposed
    single class) is ambiguous. The 5 subclasses must be siblings, not
    a chain — callers should be able to catch them independently."""
    from mordred_hermes.keyvault._exceptions import (
        WrapAuthCancelled,
        WrapIntegrityError,
        WrapKeyNotFound,
        WrapNativeUnavailable,
        WrapParseError,
    )

    classes = [
        WrapParseError,
        WrapIntegrityError,
        WrapNativeUnavailable,
        WrapAuthCancelled,
        WrapKeyNotFound,
    ]
    for cls in classes:
        for other in classes:
            if cls is not other:
                assert not issubclass(cls, other), (
                    f"{cls.__name__} unexpectedly subclasses {other.__name__} — "
                    "PR3 taxonomy requires siblings, not chains"
                )


def test_lazy_import_security_returns_security_module_on_macos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Darwin with pyobjc installed, ``_lazy_import_security()`` returns
    the imported Security module. The test injects a fake module so it
    runs on any platform; the cache slot is the integration seam."""
    import mordred_hermes.keyvault.native as native

    fake_security = type("FakeSecurity", (), {"kSecClassKey": "<sentinel>"})
    monkeypatch.setattr(native, "_security_module", fake_security)

    result = native._lazy_import_security()

    assert result is fake_security


def test_lazy_import_security_caches_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pyobjc bridge is expensive to load. Calling
    ``_lazy_import_security()`` repeatedly must return the same object
    without re-resolving."""
    import mordred_hermes.keyvault.native as native

    fake_security = type("FakeSecurity", (), {})
    monkeypatch.setattr(native, "_security_module", fake_security)

    first = native._lazy_import_security()
    second = native._lazy_import_security()

    assert first is second is fake_security


def test_lazy_import_security_raises_wrap_native_unavailable_on_non_darwin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-macOS short-circuit. ``WrapNativeUnavailable`` MUST be raised
    before any ``import Security`` is attempted (verified indirectly by
    the message containing the platform name, not an ImportError chain)."""
    import sys

    import mordred_hermes.keyvault.native as native
    from mordred_hermes.keyvault._exceptions import WrapNativeUnavailable

    monkeypatch.setattr(native, "_security_module", None)
    monkeypatch.setattr(sys, "platform", "linux")

    with pytest.raises(WrapNativeUnavailable) as excinfo:
        native._lazy_import_security()

    assert "macOS" in str(excinfo.value) or "darwin" in str(excinfo.value).lower()
    assert excinfo.value.__cause__ is None, (
        "non-darwin path should short-circuit before any ImportError; no exception chain expected"
    )


def test_lazy_import_security_raises_with_install_hint_when_pyobjc_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On macOS without pyobjc, the user needs to run
    ``pip install mordred-hermes[macos]``. The message must mention the
    extra; the ImportError must be chained via ``__cause__`` so callers
    can introspect."""
    import sys

    import mordred_hermes.keyvault.native as native
    from mordred_hermes.keyvault._exceptions import WrapNativeUnavailable

    monkeypatch.setattr(native, "_security_module", None)
    monkeypatch.setattr(sys, "platform", "darwin")

    def fake_importer() -> Any:
        raise ImportError("No module named 'Security'")

    monkeypatch.setattr(native, "_import_security_via_pyobjc", fake_importer)

    with pytest.raises(WrapNativeUnavailable) as excinfo:
        native._lazy_import_security()

    assert "macos" in str(excinfo.value).lower() or "pyobjc" in str(excinfo.value).lower()
    assert isinstance(excinfo.value.__cause__, ImportError), (
        "macOS-without-pyobjc path must chain the underlying ImportError"
    )


def test_is_secure_enclave_available_false_on_non_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Codex MEDIUM-1: capability probe must NOT touch pyobjc on non-Darwin
    (importing Security would fail or crash). Short-circuit on platform
    string first."""
    import sys

    import mordred_hermes.keyvault.native as native

    monkeypatch.setattr(native, "_security_module", None)
    monkeypatch.setattr(sys, "platform", "linux")

    assert native.is_secure_enclave_available() is False


def test_is_secure_enclave_available_true_when_probe_generates_and_deletes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capability probe is a throwaway key-generate-then-delete cycle
    using ``.privateKeyUsage`` only (no biometry → no user prompt).
    Success = True."""
    import sys

    import mordred_hermes.keyvault.native as native

    calls: list[str] = []

    def fake_probe() -> bool:
        calls.append("probed")
        return True

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(native, "_probe_secure_enclave_capability", fake_probe)

    assert native.is_secure_enclave_available() is True
    assert calls == ["probed"]


def test_is_secure_enclave_available_false_when_probe_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the probe raises (NSError, missing entitlement, T2 chip with
    SEP locked, etc.), the public API returns False rather than letting
    the exception escape — capability detection must be infallible."""
    import sys

    import mordred_hermes.keyvault.native as native

    def fake_probe() -> bool:
        raise RuntimeError("simulated SEP unavailable")

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(native, "_probe_secure_enclave_capability", fake_probe)

    assert native.is_secure_enclave_available() is False


def test_is_secure_enclave_available_false_when_native_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``_lazy_import_security`` would raise (e.g. macOS without pyobjc),
    ``is_secure_enclave_available()`` must return False rather than
    propagate — capability detection is callable from non-keyvault code
    paths (e.g. policy explain) that should not crash."""
    import sys

    import mordred_hermes.keyvault.native as native
    from mordred_hermes.keyvault._exceptions import WrapNativeUnavailable

    def fake_probe() -> bool:
        raise WrapNativeUnavailable("pyobjc missing")

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(native, "_probe_secure_enclave_capability", fake_probe)

    assert native.is_secure_enclave_available() is False
