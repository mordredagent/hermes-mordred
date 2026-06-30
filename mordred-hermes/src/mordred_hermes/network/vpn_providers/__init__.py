"""Pluggable VPN providers behind the single ``"vpn"`` network path.

Mullvad is the recommended default and the only provider that satisfies
strict mode out of the box (a Mordred-driven, verifiable kill-switch).
Later phases add a generic WireGuard (bring-your-own config) provider and
a custom-command provider so any VPN can be driven. Select a provider via
``plugins.mordred_network.vpn_provider`` in ``config.yaml``.
"""

from __future__ import annotations

from .base import DEFAULT_RUNNER, PolicyMode, SubprocessRunner, VpnCapabilities, VpnProvider
from .custom import CustomCommandProvider
from .mullvad import MullvadProvider
from .registry import build_provider, known_providers
from .wireguard import WireGuardProvider

__all__ = [
    "DEFAULT_RUNNER",
    "CustomCommandProvider",
    "MullvadProvider",
    "PolicyMode",
    "SubprocessRunner",
    "VpnCapabilities",
    "VpnProvider",
    "WireGuardProvider",
    "build_provider",
    "known_providers",
]
