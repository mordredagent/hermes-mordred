"""RED tests for Phase 4 PR5: ``keyvault.network_fallback``.

SPEC.md §Seed phrase display security:

- The primary blackout mechanism is ``mordred_network.api.blackout_assert``.
- **Fallback**: when ``mordred_network`` is not importable, ``keyvault``
  calls the OS reachability API directly (macOS ``SCNetworkReachability``
  via pyobjc) through a thin wrapper.
- ``import mordred_hermes.keyvault.network_fallback`` MUST succeed on any
  platform; the pyobjc bridge is deferred to call time (same contract as
  ``keyvault.native``).

These tests run cross-platform: every pyobjc path is exercised through a
``_FakeSystemConfiguration`` injected via ``monkeypatch.setattr``.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from mordred_hermes.keyvault import network_fallback as nf

# SCNetworkReachabilityFlags bit values (mirror of the module constants;
# kept literal here so parametrize decorators do not import module attrs
# at collection time).
_TRANSIENT = 1 << 0
_REACHABLE = 1 << 1
_CONNECTION_REQUIRED = 1 << 2
_CONNECTION_ON_TRAFFIC = 1 << 3
_CONNECTION_ON_DEMAND = 1 << 5
_IS_DIRECT = 1 << 17


class _FakeSystemConfiguration:
    """Minimal stand-in for the pyobjc ``SystemConfiguration`` module.

    Implements only the two symbols ``_query_reachability_flags`` touches.
    ``create_result`` is an opaque sentinel; ``get_flags_result`` is the
    ``(ok, flags)`` tuple the fake hands back from ``GetFlags``.
    """

    def __init__(
        self,
        *,
        create_result: object = "fake-target",
        get_flags_result: tuple[bool, int] = (True, 0),
    ) -> None:
        self._create_result = create_result
        self._get_flags_result = get_flags_result
        self.create_calls: list[Any] = []

    def SCNetworkReachabilityCreateWithName(  # mirrors the C API name
        self, allocator: Any, name: Any
    ) -> object:
        self.create_calls.append(name)
        return self._create_result

    def SCNetworkReachabilityGetFlags(  # mirrors the C API name
        self, target: Any, flags: Any
    ) -> tuple[bool, int]:
        return self._get_flags_result


# --------------------------------------------------------------------------
# Module import + exception taxonomy
# --------------------------------------------------------------------------


def test_module_imports_on_any_platform() -> None:
    """``network_fallback`` must import cleanly on Linux/Windows so the
    non-keyvault primitives stay usable; pyobjc is deferred to call time.
    """
    import mordred_hermes.keyvault.network_fallback  # noqa: F401


def test_exception_taxonomy() -> None:
    """``BlackoutNotAsserted`` and ``NetworkFallbackUnavailable`` are the
    two keyvault-owned exceptions the module raises. Both are ordinary
    ``Exception`` subclasses — the fallback runs inside ``keyvault.api`` /
    ``seed_display`` and has no need to escape Hermes' ``invoke_hook``
    filter. The two are siblings, not a chain.
    """
    assert issubclass(nf.BlackoutNotAsserted, Exception)
    assert issubclass(nf.NetworkFallbackUnavailable, Exception)
    assert not issubclass(nf.NetworkFallbackUnavailable, nf.BlackoutNotAsserted)
    assert not issubclass(nf.BlackoutNotAsserted, nf.NetworkFallbackUnavailable)


def test_probe_host_backward_compat_alias_removed() -> None:
    """LOW dead-code finding: ``_PROBE_HOST`` was a "backward-compat alias"
    for ``_PROBE_HOST_V4`` with zero remaining consumers (the real probe in
    ``_os_reachability_probe`` uses ``_PROBE_HOST_V4`` / ``_PROBE_HOST_V6``
    directly). Pin its removal so it does not silently creep back in as
    dead state — the two live constants must still be defined and distinct."""
    assert not hasattr(nf, "_PROBE_HOST")
    assert nf._PROBE_HOST_V4 != nf._PROBE_HOST_V6


# --------------------------------------------------------------------------
# _interpret_reachability_flags — pure flag logic
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "expected", "why"),
    [
        (0, False, "no flags == air-gapped host"),
        (_REACHABLE, True, "Reachable set, no caveats == online"),
        (_CONNECTION_REQUIRED, False, "ConnectionRequired without Reachable"),
        (
            _REACHABLE | _CONNECTION_REQUIRED,
            False,
            "Reachable but a connection must be brought up first",
        ),
        (_REACHABLE | _TRANSIENT, True, "transient (e.g. PPP up) still reachable"),
        (_REACHABLE | _IS_DIRECT, True, "direct interface route, reachable"),
        (
            _REACHABLE | _CONNECTION_ON_DEMAND,
            True,
            "on-demand path advertised reachable without ConnectionRequired",
        ),
        (_CONNECTION_ON_TRAFFIC, False, "dormant on-traffic path, not Reachable"),
    ],
)
def test_interpret_reachability_flags(flags: int, expected: bool, why: str) -> None:
    """``_interpret_reachability_flags`` returns True == host has a usable
    network path right now (== NOT blacked out). The rule is the standard
    Apple interpretation: ``Reachable`` set AND ``ConnectionRequired`` clear.
    """
    assert nf._interpret_reachability_flags(flags) is expected, why


# --------------------------------------------------------------------------
# _query_reachability_flags — pyobjc boundary
# --------------------------------------------------------------------------


def test_query_reachability_flags_non_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    """On non-macOS hosts the OS probe is unavailable; ``__cause__`` is
    ``None`` (short-circuit before any import attempt)."""
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(nf.NetworkFallbackUnavailable) as excinfo:
        nf._query_reachability_flags()
    assert excinfo.value.__cause__ is None


def test_query_reachability_flags_pyobjc_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """macOS without ``pyobjc-framework-SystemConfiguration``: the
    underlying ``ImportError`` is chained via ``__cause__``."""
    monkeypatch.setattr(sys, "platform", "darwin")

    def _raise_import_error() -> Any:
        raise ImportError("No module named 'SystemConfiguration'")

    monkeypatch.setattr(nf, "_import_systemconfiguration", _raise_import_error)
    with pytest.raises(nf.NetworkFallbackUnavailable) as excinfo:
        nf._query_reachability_flags()
    assert isinstance(excinfo.value.__cause__, ImportError)


def test_query_reachability_flags_returns_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: the raw ``SCNetworkReachabilityGetFlags`` value is
    returned verbatim as an ``int``."""
    monkeypatch.setattr(sys, "platform", "darwin")
    fake = _FakeSystemConfiguration(get_flags_result=(True, _REACHABLE))
    monkeypatch.setattr(nf, "_import_systemconfiguration", lambda: fake)
    assert nf._query_reachability_flags() == _REACHABLE


def test_query_reachability_flags_create_returns_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``SCNetworkReachabilityCreateWithName`` returning NULL surfaces as
    ``NetworkFallbackUnavailable``, not a silent ``False``."""
    monkeypatch.setattr(sys, "platform", "darwin")
    fake = _FakeSystemConfiguration(create_result=None)
    monkeypatch.setattr(nf, "_import_systemconfiguration", lambda: fake)
    with pytest.raises(nf.NetworkFallbackUnavailable):
        nf._query_reachability_flags()


def test_query_reachability_flags_get_flags_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``SCNetworkReachabilityGetFlags`` returning ``ok=False`` surfaces as
    ``NetworkFallbackUnavailable`` rather than trusting the flags."""
    monkeypatch.setattr(sys, "platform", "darwin")
    fake = _FakeSystemConfiguration(get_flags_result=(False, 0))
    monkeypatch.setattr(nf, "_import_systemconfiguration", lambda: fake)
    with pytest.raises(nf.NetworkFallbackUnavailable):
        nf._query_reachability_flags()


def test_query_reachability_flags_bridge_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unexpected pyobjc-bridge error (objc.error, etc.) must be funnelled
    into ``NetworkFallbackUnavailable`` so it never escapes as a foreign type
    — ``blackout_assert``'s fail-closed catch depends on this."""
    monkeypatch.setattr(sys, "platform", "darwin")

    class _RaisingSC:
        def SCNetworkReachabilityCreateWithName(  # mirrors the C API name
            self, allocator: Any, name: Any
        ) -> object:
            raise RuntimeError("objc bridge blew up")

    monkeypatch.setattr(nf, "_import_systemconfiguration", lambda: _RaisingSC())
    with pytest.raises(nf.NetworkFallbackUnavailable) as excinfo:
        nf._query_reachability_flags()
    assert isinstance(excinfo.value.__cause__, RuntimeError)


def test_query_reachability_flags_malformed_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed ``SCNetworkReachabilityGetFlags`` return that breaks the
    ``ok, flags`` unpack surfaces as ``NetworkFallbackUnavailable``, not a
    raw ``ValueError``."""
    monkeypatch.setattr(sys, "platform", "darwin")

    class _MalformedSC:
        def SCNetworkReachabilityCreateWithName(  # mirrors the C API name
            self, allocator: Any, name: Any
        ) -> object:
            return "fake-target"

        def SCNetworkReachabilityGetFlags(  # mirrors the C API name
            self, target: Any, flags: Any
        ) -> object:
            return "not-a-two-tuple"

    monkeypatch.setattr(nf, "_import_systemconfiguration", lambda: _MalformedSC())
    with pytest.raises(nf.NetworkFallbackUnavailable):
        nf._query_reachability_flags()


# --------------------------------------------------------------------------
# _os_reachability_probe — query + interpret
# --------------------------------------------------------------------------


def test_os_reachability_probe_online(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nf, "_query_reachability_flags", lambda *_a: _REACHABLE)
    assert nf._os_reachability_probe() is True


def test_os_reachability_probe_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nf, "_query_reachability_flags", lambda *_a: 0)
    assert nf._os_reachability_probe() is False


def test_os_reachability_probe_detects_ipv6_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Security review H3: a dual-stack host whose IPv4 is down but whose
    IPv6 still routes is NOT isolated. The OS fallback must probe both
    families and report reachable if EITHER routes — mirroring the
    primary ``mordred_network`` probe."""

    def _flags(host: bytes = b"1.1.1.1") -> int:
        # IPv6 literal contains colons; only it is reachable here.
        return _REACHABLE if b":" in host else 0

    monkeypatch.setattr(nf, "_query_reachability_flags", _flags)
    assert nf._os_reachability_probe() is True


def test_os_reachability_probe_propagates_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A probe that cannot run must NOT be coerced to ``False`` (that would
    let a seed display through on an un-probeable host)."""

    def _raise(*_a: object) -> int:
        raise nf.NetworkFallbackUnavailable("no probe")

    monkeypatch.setattr(nf, "_query_reachability_flags", _raise)
    with pytest.raises(nf.NetworkFallbackUnavailable):
        nf._os_reachability_probe()


# --------------------------------------------------------------------------
# blackout_assert
# --------------------------------------------------------------------------


def test_blackout_assert_offline_returns() -> None:
    """Injected probe reports offline -> no exception."""
    nf.blackout_assert(probe=lambda: False)


def test_blackout_assert_online_raises() -> None:
    """Injected probe reports reachable -> ``BlackoutNotAsserted``."""
    with pytest.raises(nf.BlackoutNotAsserted):
        nf.blackout_assert(probe=lambda: True)


def test_blackout_assert_default_probe_offline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no explicit probe, ``_os_reachability_probe`` is used."""
    monkeypatch.setattr(nf, "_os_reachability_probe", lambda: False)
    nf.blackout_assert()


def test_blackout_assert_default_probe_online(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nf, "_os_reachability_probe", lambda: True)
    with pytest.raises(nf.BlackoutNotAsserted):
        nf.blackout_assert()


def test_blackout_assert_fails_closed_when_probe_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the probe cannot run, ``blackout_assert`` MUST refuse (fail
    closed) — raising ``BlackoutNotAsserted`` with the underlying
    ``NetworkFallbackUnavailable`` chained for diagnostics."""

    def _raise() -> bool:
        raise nf.NetworkFallbackUnavailable("no OS probe")

    monkeypatch.setattr(nf, "_os_reachability_probe", _raise)
    with pytest.raises(nf.BlackoutNotAsserted) as excinfo:
        nf.blackout_assert()
    assert isinstance(excinfo.value.__cause__, nf.NetworkFallbackUnavailable)


# --------------------------------------------------------------------------
# resolve_blackout_assert
# --------------------------------------------------------------------------


def test_resolve_uses_mordred_network_when_importable() -> None:
    """When ``mordred_network`` is importable (the v1 single-package
    default), the resolved callable delegates to it without raising for an
    offline probe."""
    resolved = nf.resolve_blackout_assert()
    resolved(probe=lambda: False)


def test_resolve_delegation_translates_exception() -> None:
    """The delegating wrapper translates ``mordred_network``'s
    ``BlackoutNotAsserted`` into the keyvault-local one, so a caller only
    ever needs to catch ``network_fallback.BlackoutNotAsserted``."""
    from mordred_hermes.network._exceptions import (
        BlackoutNotAsserted as NetworkBlackoutNotAsserted,
    )

    resolved = nf.resolve_blackout_assert()
    with pytest.raises(nf.BlackoutNotAsserted) as excinfo:
        resolved(probe=lambda: True)
    assert isinstance(excinfo.value.__cause__, NetworkBlackoutNotAsserted)


def test_resolve_falls_back_when_network_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``mordred_network`` is not importable, ``resolve_blackout_assert``
    returns this module's own OS-API ``blackout_assert``."""

    def _raise_import_error() -> Any:
        raise ImportError("No module named 'mordred_hermes.network'")

    monkeypatch.setattr(nf, "_import_network_api", _raise_import_error)
    resolved = nf.resolve_blackout_assert()
    assert resolved is nf.blackout_assert


def test_resolve_fallback_callable_uses_os_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fallback callable raises the keyvault ``BlackoutNotAsserted``
    when the OS probe reports reachability."""

    def _raise_import_error() -> Any:
        raise ImportError("absent")

    monkeypatch.setattr(nf, "_import_network_api", _raise_import_error)
    monkeypatch.setattr(nf, "_os_reachability_probe", lambda: True)
    resolved = nf.resolve_blackout_assert()
    with pytest.raises(nf.BlackoutNotAsserted):
        resolved()
