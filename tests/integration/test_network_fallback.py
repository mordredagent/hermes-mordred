"""Integration test: keyvault network-blackout fallback (Phase 4 PR10, L454).

Acceptance gate L454 — "In ``mordred_network``-absent envs, ``keyvault
init`` still functions via OS API fallback". ``keyvault.seed_display``
asserts a network blackout before showing the Seed; it resolves the
assert through :func:`network_fallback.resolve_blackout_assert`, which
delegates to ``mordred_network`` when present and falls back to a direct
OS reachability probe when it is not.

In a v1 single-package install ``mordred_network`` is always importable,
so the absent case is exercised by substituting an ``ImportError``-raising
import seam (``network_fallback._import_network_api``) — the same seam
the module docstring documents for this purpose.
"""

from __future__ import annotations

import pytest

from mordred_hermes.keyvault import network_fallback as nf


def _raise_import_error() -> object:
    """Stand-in for the ``mordred_network`` import seam when it is absent."""
    raise ImportError("mordred_network is not installed")


class TestNetworkAbsentFallback:
    """``mordred_network`` not importable → the OS-API probe is used."""

    def test_fallback_returns_os_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nf, "_import_network_api", _raise_import_error)
        assert nf.resolve_blackout_assert() is nf.blackout_assert

    def test_fallback_passes_when_host_isolated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nf, "_import_network_api", _raise_import_error)
        resolved = nf.resolve_blackout_assert()
        # An isolated host (probe → False) must not raise.
        resolved(probe=lambda: False)

    def test_fallback_raises_when_host_reachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nf, "_import_network_api", _raise_import_error)
        resolved = nf.resolve_blackout_assert()
        with pytest.raises(nf.BlackoutNotAsserted):
            resolved(probe=lambda: True)

    def test_fallback_fails_closed_when_probe_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A probe that cannot run (non-macOS / no pyobjc) must still
        refuse the Seed display — fail closed, never fail open."""
        monkeypatch.setattr(nf, "_import_network_api", _raise_import_error)
        resolved = nf.resolve_blackout_assert()

        def _unavailable_probe() -> bool:
            raise nf.NetworkFallbackUnavailable("OS reachability probe cannot run here")

        with pytest.raises(nf.BlackoutNotAsserted):
            resolved(probe=_unavailable_probe)


class TestNetworkPresentDelegation:
    """``mordred_network`` importable → the assert delegates to it."""

    def test_primary_path_used_when_network_present(self) -> None:
        resolved = nf.resolve_blackout_assert()
        # The delegating wrapper, not the bare OS-API blackout_assert.
        assert resolved is not nf.blackout_assert

    def test_delegated_assert_raises_keyvault_owned_exception(self) -> None:
        """A reachable host surfaces keyvault's BlackoutNotAsserted, not
        ``mordred_network``'s — callers catch a single type."""
        resolved = nf.resolve_blackout_assert()
        with pytest.raises(nf.BlackoutNotAsserted):
            resolved(probe=lambda: True)
