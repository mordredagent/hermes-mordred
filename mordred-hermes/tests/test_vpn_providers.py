"""Tests for the pluggable VPN provider layer.

Phase 1 of "use any VPN, not just Mullvad": the ``"vpn"`` network path
stays a single route, but the provider *behind* it is selectable. This
module covers the provider abstraction itself:

- :class:`VpnCapabilities` carries the strict-mode guarantees a provider
  can (or cannot) make — the kill-switch / DNS-leak flags the runtime's
  strict gate reads (Phase 2).
- :func:`build_provider` resolves a provider by name, defaulting to
  Mullvad so existing configs keep working unchanged.
- :class:`MullvadProvider` declares ``killswitch=True`` (Mordred drives
  ``mullvad lockdown-mode`` directly) and delegates the bring-up /
  teardown / health work to the existing :mod:`...network.paths.vpn`
  module, so the refactor is behaviour-preserving.

The Mullvad CLI is fully mocked through the injectable runner — no real
client is touched.
"""

from __future__ import annotations

import subprocess

import pytest


class _FakeRunner:
    """Captures every ``subprocess.run``-shaped call for assertion."""

    def __init__(self, responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del check, capture_output, text, timeout
        key = tuple(argv)
        self.calls.append(key)
        try:
            return self._responses[key]
        except KeyError:
            return subprocess.CompletedProcess(args=list(key), returncode=0, stdout="", stderr="")


def _result(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# --------------------------------------------------------------------------- #
# Capabilities                                                                #
# --------------------------------------------------------------------------- #


class TestVpnCapabilities:
    def test_fields(self) -> None:
        from mordred_hermes.network.vpn_providers import VpnCapabilities

        caps = VpnCapabilities(killswitch=True, dns_leak_safe=False)
        assert caps.killswitch is True
        assert caps.dns_leak_safe is False

    def test_is_immutable(self) -> None:
        from dataclasses import FrozenInstanceError

        from mordred_hermes.network.vpn_providers import VpnCapabilities

        caps = VpnCapabilities(killswitch=True, dns_leak_safe=True)
        with pytest.raises(FrozenInstanceError):
            caps.killswitch = False  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Registry                                                                    #
# --------------------------------------------------------------------------- #


class TestRegistry:
    def test_runtime_config_defaults_to_mullvad(self) -> None:
        """Existing configs (no vpn_provider key) must keep using Mullvad."""
        from mordred_hermes.network.runtime import RuntimeConfig

        assert RuntimeConfig().vpn_provider == "mullvad"

    def test_build_mullvad_explicit(self) -> None:
        from mordred_hermes.network.vpn_providers import MullvadProvider, build_provider

        provider = build_provider("mullvad")
        assert isinstance(provider, MullvadProvider)
        assert provider.name == "mullvad"

    def test_unknown_provider_raises(self) -> None:
        from mordred_hermes.network._exceptions import UnknownVpnProvider
        from mordred_hermes.network.vpn_providers import build_provider

        with pytest.raises(UnknownVpnProvider) as excinfo:
            build_provider("totally-not-a-vpn")
        # Message should name the bad value and list the known providers.
        msg = str(excinfo.value)
        assert "totally-not-a-vpn" in msg
        assert "mullvad" in msg


# --------------------------------------------------------------------------- #
# MullvadProvider — capabilities + faithful delegation                        #
# --------------------------------------------------------------------------- #


class TestMullvadProviderCapabilities:
    def test_declares_killswitch_and_dns_leak_safe(self) -> None:
        from mordred_hermes.network.vpn_providers import MullvadProvider

        caps = MullvadProvider().capabilities
        # Mordred drives `mullvad lockdown-mode` and Mullvad forces in-tunnel
        # DNS, so it is the one provider that fully satisfies strict mode.
        assert caps.killswitch is True
        assert caps.dns_leak_safe is True


class TestMullvadProviderDelegation:
    """The provider must behave exactly like the underlying paths.vpn
    module so converting the runtime to the provider seam changes no
    Mullvad behaviour.
    """

    def test_detect_cli_resolves_from_which(self) -> None:
        from mordred_hermes.network.vpn_providers import MullvadProvider

        provider = MullvadProvider()
        assert provider.detect_cli(which=lambda name: "/opt/homebrew/bin/mullvad") == "/opt/homebrew/bin/mullvad"

    def test_bring_up_issues_connect_in_order(self) -> None:
        from mordred_hermes.network.vpn_providers import MullvadProvider

        runner = _FakeRunner({})
        provider = MullvadProvider()
        handle = provider.bring_up(
            cli_path="/bin/mullvad",
            region="jp",
            policy_mode="strict",
            runner=runner,
        )
        assert ("/bin/mullvad", "lockdown-mode", "set", "on") in runner.calls
        assert ("/bin/mullvad", "relay", "set", "location", "jp") in runner.calls
        assert ("/bin/mullvad", "connect") in runner.calls
        # Handle carries Mullvad state the runtime teardown relies on.
        assert handle.cli_path == "/bin/mullvad"
        assert handle.lockdown_enforced is True

    def test_wait_connected_polls_status(self) -> None:
        from mordred_hermes.network.vpn_providers import MullvadProvider

        runner = _FakeRunner({("/bin/mullvad", "status"): _result(stdout="Tunnel status: Connected\n")})
        provider = MullvadProvider()
        provider.wait_connected(cli_path="/bin/mullvad", runner=runner)
        assert ("/bin/mullvad", "status") in runner.calls

    def test_disconnect_preserves_lockdown_by_default(self) -> None:
        from mordred_hermes.network.paths import vpn as vpn_mod
        from mordred_hermes.network.vpn_providers import MullvadProvider

        runner = _FakeRunner({})
        handle = vpn_mod.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        MullvadProvider().disconnect(handle, runner=runner)
        assert ("/bin/mullvad", "disconnect") in runner.calls
        assert ("/bin/mullvad", "lockdown-mode", "set", "off") not in runner.calls

    def test_health_reads_handshake_freshness(self) -> None:
        from mordred_hermes.network.paths import vpn as vpn_mod
        from mordred_hermes.network.vpn_providers import MullvadProvider

        runner = _FakeRunner({("wg", "show"): _result(stdout="latest handshake: 30 seconds ago\n")})
        handle = vpn_mod.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert MullvadProvider().health(handle, runner=runner) is True


# --------------------------------------------------------------------------- #
# WireGuard provider (generic, bring-your-own config — Proton, IVPN, etc.)     #
# --------------------------------------------------------------------------- #


class TestWireGuardProvider:
    """Generic ``wg-quick`` provider: drives a user-supplied WireGuard
    config. Covers any VPN that exports a ``.conf`` (Proton VPN, IVPN,
    Windscribe, self-hosted). No vendor kill-switch CLI, so
    ``capabilities.killswitch`` is False — strict mode refuses it.
    """

    _CONF = "/etc/wireguard/wg0.conf"

    def test_registry_builds_wireguard(self) -> None:
        from mordred_hermes.network.vpn_providers import WireGuardProvider, build_provider

        provider = build_provider("wireguard", wireguard_config_path=self._CONF)
        assert isinstance(provider, WireGuardProvider)
        assert provider.name == "wireguard"

    def test_capabilities_have_no_killswitch(self) -> None:
        from mordred_hermes.network.vpn_providers import WireGuardProvider

        caps = WireGuardProvider(config_path=self._CONF).capabilities
        assert caps.killswitch is False

    def test_detect_cli_resolves_wg_quick(self) -> None:
        from mordred_hermes.network.vpn_providers import WireGuardProvider

        provider = WireGuardProvider(config_path=self._CONF)
        assert provider.detect_cli(which=lambda name: "/opt/homebrew/bin/wg-quick") == "/opt/homebrew/bin/wg-quick"

    def test_detect_cli_missing_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.vpn_providers import WireGuardProvider

        provider = WireGuardProvider(config_path=self._CONF)
        with pytest.raises(BringupFailed) as excinfo:
            provider.detect_cli(which=lambda name: None)
        assert "wg-quick" in str(excinfo.value)

    def test_bring_up_runs_wg_quick_up(self) -> None:
        from mordred_hermes.network.vpn_providers import WireGuardProvider

        runner = _FakeRunner({})
        provider = WireGuardProvider(config_path=self._CONF, exists=lambda _p: True)
        handle = provider.bring_up(cli_path="/usr/bin/wg-quick", region="auto", policy_mode="off", runner=runner)
        assert ("/usr/bin/wg-quick", "up", self._CONF) in runner.calls
        assert handle.config_path == self._CONF

    def test_bring_up_missing_config_file_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.vpn_providers import WireGuardProvider

        runner = _FakeRunner({})
        provider = WireGuardProvider(config_path=self._CONF, exists=lambda _p: False)
        with pytest.raises(BringupFailed):
            provider.bring_up(cli_path="/usr/bin/wg-quick", region="auto", policy_mode="off", runner=runner)

    def test_bring_up_without_configured_path_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.vpn_providers import WireGuardProvider

        runner = _FakeRunner({})
        provider = WireGuardProvider(config_path=None)
        with pytest.raises(BringupFailed):
            provider.bring_up(cli_path="/usr/bin/wg-quick", region="auto", policy_mode="off", runner=runner)

    def test_bring_up_nonzero_returncode_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.vpn_providers import WireGuardProvider

        runner = _FakeRunner({("/usr/bin/wg-quick", "up", self._CONF): _result(returncode=1)})
        provider = WireGuardProvider(config_path=self._CONF, exists=lambda _p: True)
        with pytest.raises(BringupFailed):
            provider.bring_up(cli_path="/usr/bin/wg-quick", region="auto", policy_mode="off", runner=runner)

    def test_disconnect_runs_wg_quick_down(self) -> None:
        from mordred_hermes.network.vpn_providers import WireGuardProvider
        from mordred_hermes.network.vpn_providers.wireguard import WireGuardHandle

        runner = _FakeRunner({})
        handle = WireGuardHandle(wg_quick_path="/usr/bin/wg-quick", config_path=self._CONF)
        WireGuardProvider(config_path=self._CONF).disconnect(handle, runner=runner)
        assert ("/usr/bin/wg-quick", "down", self._CONF) in runner.calls

    def test_health_fresh_handshake_is_healthy(self) -> None:
        from mordred_hermes.network.vpn_providers import WireGuardProvider
        from mordred_hermes.network.vpn_providers.wireguard import WireGuardHandle

        runner = _FakeRunner({("wg", "show", "wg0"): _result(stdout="latest handshake: 20 seconds ago\n")})
        handle = WireGuardHandle(wg_quick_path="/usr/bin/wg-quick", config_path=self._CONF)
        assert WireGuardProvider(config_path=self._CONF).health(handle, runner=runner) is True

    def test_health_stale_handshake_is_unhealthy(self) -> None:
        from mordred_hermes.network.vpn_providers import WireGuardProvider
        from mordred_hermes.network.vpn_providers.wireguard import WireGuardHandle

        runner = _FakeRunner({("wg", "show", "wg0"): _result(stdout="latest handshake: 12 minutes ago\n")})
        handle = WireGuardHandle(wg_quick_path="/usr/bin/wg-quick", config_path=self._CONF)
        assert WireGuardProvider(config_path=self._CONF).health(handle, runner=runner) is False


# --------------------------------------------------------------------------- #
# Custom-command provider (the 'any VPN' escape hatch — ExpressVPN, NordVPN)   #
# --------------------------------------------------------------------------- #


class TestCustomCommandProvider:
    """Custom-command provider: drives user-configured up/down/health argv
    so a VPN with only its own CLI (ExpressVPN, NordVPN, Surfshark) works.
    argv only — never a shell — and commands come from config.yaml
    (operator-controlled), so there is no shell-injection surface.
    ``killswitch=False`` so strict mode refuses it.
    """

    _UP = ("expressvpn", "connect")
    _DOWN = ("expressvpn", "disconnect")
    _HEALTH = ("expressvpn", "status")

    def test_registry_builds_custom(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider, build_provider

        provider = build_provider(
            "custom",
            custom_up_cmd=self._UP,
            custom_down_cmd=self._DOWN,
            custom_health_cmd=self._HEALTH,
        )
        assert isinstance(provider, CustomCommandProvider)
        assert provider.name == "custom"

    def test_capabilities_have_no_killswitch(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider

        caps = CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN).capabilities
        assert caps.killswitch is False

    def test_detect_cli_resolves_up_binary(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider

        provider = CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN)
        assert provider.detect_cli(which=lambda name: "/usr/bin/expressvpn") == "/usr/bin/expressvpn"

    def test_detect_cli_missing_binary_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.vpn_providers import CustomCommandProvider

        provider = CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN)
        with pytest.raises(BringupFailed):
            provider.detect_cli(which=lambda name: None)

    def test_detect_cli_without_up_cmd_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.vpn_providers import CustomCommandProvider

        provider = CustomCommandProvider(up_cmd=(), down_cmd=self._DOWN)
        with pytest.raises(BringupFailed):
            provider.detect_cli(which=lambda name: "/usr/bin/anything")

    def test_bring_up_runs_up_cmd(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider

        runner = _FakeRunner({})
        provider = CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN, health_cmd=self._HEALTH)
        provider.bring_up(cli_path="expressvpn", region="auto", policy_mode="off", runner=runner)
        assert ("expressvpn", "connect") in runner.calls

    def test_bring_up_nonzero_returncode_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.vpn_providers import CustomCommandProvider

        runner = _FakeRunner({self._UP: _result(returncode=1)})
        provider = CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN)
        with pytest.raises(BringupFailed):
            provider.bring_up(cli_path="expressvpn", region="auto", policy_mode="off", runner=runner)

    def test_disconnect_runs_down_cmd(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider
        from mordred_hermes.network.vpn_providers.custom import CustomHandle

        runner = _FakeRunner({})
        handle = CustomHandle(down_cmd=self._DOWN, health_cmd=self._HEALTH)
        CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN).disconnect(handle, runner=runner)
        assert ("expressvpn", "disconnect") in runner.calls

    def test_health_runs_health_cmd(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider
        from mordred_hermes.network.vpn_providers.custom import CustomHandle

        runner = _FakeRunner({self._HEALTH: _result(returncode=0)})
        handle = CustomHandle(down_cmd=self._DOWN, health_cmd=self._HEALTH)
        assert CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN).health(handle, runner=runner) is True

    def test_health_nonzero_is_unhealthy(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider
        from mordred_hermes.network.vpn_providers.custom import CustomHandle

        runner = _FakeRunner({self._HEALTH: _result(returncode=1)})
        handle = CustomHandle(down_cmd=self._DOWN, health_cmd=self._HEALTH)
        assert CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN).health(handle, runner=runner) is False

    def test_health_without_health_cmd_assumes_healthy(self) -> None:
        from mordred_hermes.network.vpn_providers import CustomCommandProvider
        from mordred_hermes.network.vpn_providers.custom import CustomHandle

        runner = _FakeRunner({})
        handle = CustomHandle(down_cmd=self._DOWN, health_cmd=None)
        # No probe configured -> cannot observe a drop -> reported healthy.
        assert CustomCommandProvider(up_cmd=self._UP, down_cmd=self._DOWN).health(handle, runner=runner) is True


# --------------------------------------------------------------------------- #
# Protocol conformance                                                        #
# --------------------------------------------------------------------------- #


def test_mullvad_provider_satisfies_protocol() -> None:
    from mordred_hermes.network.vpn_providers import MullvadProvider, VpnProvider

    provider: VpnProvider = MullvadProvider()
    assert provider.name == "mullvad"
    assert provider.capabilities.killswitch is True


def test_wireguard_provider_satisfies_protocol() -> None:
    from mordred_hermes.network.vpn_providers import VpnProvider, WireGuardProvider

    provider: VpnProvider = WireGuardProvider(config_path="/etc/wireguard/wg0.conf")
    assert provider.name == "wireguard"
    assert provider.capabilities.killswitch is False
