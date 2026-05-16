"""Lazy ``Security.framework`` wrapper for ``mordred_keyvault.wrap``.

Phase 4 PR3 step-A. The contract is frozen in SPEC.md §Wrap wire format
& algorithm (2026-05-14):

1. ``import mordred_hermes.keyvault.native`` must succeed on **any**
   platform. The pyobjc bridge is deferred to call time so that
   ``mordred_hermes.keyvault.{digest, backup, recovery}`` (PR2
   primitives) remain importable on Linux/Windows hosts.
2. ``_lazy_import_security()`` returns the Security module on Darwin
   with pyobjc installed; raises :class:`WrapNativeUnavailable`
   otherwise (chained from :class:`ImportError` on macOS without
   pyobjc, no chain on non-Darwin).
3. ``is_secure_enclave_available()`` probes capability via a throwaway
   key-generate-then-delete cycle (codex review MEDIUM-1). The probe is
   the only API that should be allowed to swallow exceptions: callers
   like ``hermes mordred policy explain`` cannot crash on capability
   detection.

This module deliberately does NOT export the Enclave-key generate /
ECDH / Keychain-lookup helpers — those live in ``wrap.py`` as part of
the ``NativeBackend`` Protocol implementation. ``native.py`` is the
narrow boundary between pure-Python (everything else in keyvault) and
pyobjc.

Testing seams:

- ``_security_module`` (module-level cache) — tests inject a fake
  Security namespace via ``monkeypatch.setattr``.
- ``_import_security_via_pyobjc`` (indirection) — tests substitute a
  function that raises :class:`ImportError` to exercise the
  pyobjc-missing path on non-macOS hosts.
- ``_probe_secure_enclave_capability`` (indirection) — tests substitute
  to verify ``is_secure_enclave_available`` swallows probe failures.
"""

from __future__ import annotations

import importlib
import sys
from typing import Any

from ._exceptions import WrapNativeUnavailable

_security_module: Any | None = None
"""Cached pyobjc ``Security`` module reference.

Set to ``None`` at import time. First successful
:func:`_lazy_import_security` call populates it. Tests bypass the
import by ``monkeypatch.setattr(native, "_security_module", fake)``.
"""


def _import_security_via_pyobjc() -> Any:
    """Indirection point for the actual ``import Security``.

    Extracted so tests can substitute a function that raises
    :class:`ImportError` without needing to manipulate ``sys.modules``.
    Production path uses :func:`importlib.import_module` (rather than a
    plain ``import Security`` statement) so mypy does not need to
    statically resolve the pyobjc bundle on non-macOS CI runners where
    the module is not installed — mypy strict runs on both Ubuntu and
    macOS in CI, and pyobjc is only present in the ``[macos]`` extra.
    """
    return importlib.import_module("Security")


def _lazy_import_security() -> Any:
    """Return the pyobjc ``Security`` module, importing on first call.

    Raises:
        WrapNativeUnavailable: When the host is not macOS, or when
            macOS lacks ``pyobjc-framework-Security`` (in which case
            the underlying :class:`ImportError` is chained via
            ``__cause__`` for callers that want to introspect).
    """
    global _security_module

    if _security_module is not None:
        return _security_module

    if sys.platform != "darwin":
        raise WrapNativeUnavailable(
            f"Secure Enclave requires macOS; current platform is {sys.platform!r}. "
            "Install on an Apple Silicon or T2 Intel Mac to use mordred_keyvault."
        )

    try:
        module = _import_security_via_pyobjc()
    except ImportError as exc:
        raise WrapNativeUnavailable(
            "pyobjc-framework-Security is not installed; "
            "run `pip install mordred-hermes[macos]` to enable keyvault on macOS."
        ) from exc

    _security_module = module
    return module


def _probe_secure_enclave_capability() -> bool:
    """Generate and immediately delete a throwaway Enclave key.

    The probe uses ``.privateKeyUsage`` only (no biometry / passcode
    flag) so the system cannot show a UI prompt — failure modes are
    "no SEP available" (T1 Intel Mac, Linux VM masquerading as macOS,
    locked SEP) or "pyobjc bridge missing", both of which mean the
    Enclave is unusable.

    Returns:
        True if the round-trip succeeds, False otherwise.

    Raises:
        Any exception raised by the underlying pyobjc call. The public
        wrapper :func:`is_secure_enclave_available` catches everything,
        so production callers see only a ``bool``. The raising form is
        kept distinct so the production wrapper can layer
        :class:`WrapNativeUnavailable` handling around it.

    Note:
        Delegates to :func:`_seckey_backend.probe_capability`, which
        generates and immediately deletes a ``.privateKeyUsage``-only
        Enclave key (no biometry flag → no prompt). Tests override this
        function via ``monkeypatch.setattr``; the production code path
        is exercised only on macOS arm64 / T2 with
        ``MORDRED_KEYVAULT_LIVE=1`` (live integration test).
    """
    _lazy_import_security()  # Surface WrapNativeUnavailable early.

    # Local import: ``_seckey_backend`` imports ``native`` at module
    # scope for ``_lazy_import_security``; importing it here (rather than
    # at the top of this file) keeps that dependency one-directional and
    # avoids a circular import at load time.
    from . import _seckey_backend

    return _seckey_backend.probe_capability()


def is_secure_enclave_available() -> bool:
    """Return True if a Secure Enclave round-trip is reachable.

    Infallible: any exception (NSError, missing entitlement, pyobjc
    bridge failure, T1 chip with no SEP) is swallowed and reported as
    ``False``. The public surface is callable from ``hermes mordred
    policy explain`` and similar diagnostic paths that must not crash
    on capability detection.

    Does NOT inspect ``platform.machine()``: T2 Intel Macs also have a
    reachable Secure Enclave (codex review MEDIUM-1). Capability is
    determined by trying the actual operation.

    On non-Darwin the function returns ``False`` without invoking
    pyobjc at all, so Linux / Windows installs of ``mordred-hermes``
    (without the ``[macos]`` extra) never load the Security bridge.
    """
    if sys.platform != "darwin":
        return False

    try:
        return _probe_secure_enclave_capability()
    except Exception:
        return False
