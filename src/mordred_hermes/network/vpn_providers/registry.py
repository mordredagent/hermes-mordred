"""Resolve a VPN provider by name (the ``vpn_provider`` config value).

Mullvad is the recommended default; later phases register a generic
WireGuard (bring-your-own config) provider and a custom-command provider
so any VPN can be used. Unknown names raise :class:`UnknownVpnProvider`
with the list of known providers so the wizard / CLI can guide the user
to a valid value rather than failing opaquely at bring-up time.
"""

from __future__ import annotations

from .._exceptions import UnknownVpnProvider
from .base import VpnProvider
from .custom import CustomCommandProvider
from .mullvad import MullvadProvider
from .wireguard import WireGuardProvider

__all__ = ["build_provider", "known_providers"]

#: Registered provider names — for wizard / CLI choices and error messages.
_KNOWN: tuple[str, ...] = ("mullvad", "wireguard", "custom")


def known_providers() -> tuple[str, ...]:
    """Names accepted by :func:`build_provider`, for wizard/CLI choices."""
    return _KNOWN


def build_provider(
    name: str,
    *,
    wireguard_config_path: str | None = None,
    custom_up_cmd: tuple[str, ...] = (),
    custom_down_cmd: tuple[str, ...] = (),
    custom_health_cmd: tuple[str, ...] | None = None,
) -> VpnProvider:
    """Return a provider instance for ``name``.

    Provider-specific configuration is passed as keyword arguments and
    ignored by providers that do not need it (e.g. ``wireguard_config_path``
    matters only for WireGuard; the ``custom_*`` argv only for custom).
    Raises :class:`UnknownVpnProvider` (a recoverable
    :class:`MordredNetworkError`) listing the known providers when the
    name is not registered.
    """
    if name == "mullvad":
        return MullvadProvider()
    if name == "wireguard":
        return WireGuardProvider(config_path=wireguard_config_path)
    if name == "custom":
        return CustomCommandProvider(
            up_cmd=custom_up_cmd,
            down_cmd=custom_down_cmd,
            health_cmd=custom_health_cmd,
        )
    known = ", ".join(_KNOWN)
    raise UnknownVpnProvider(f"unknown VPN provider {name!r}; known providers: {known}")
