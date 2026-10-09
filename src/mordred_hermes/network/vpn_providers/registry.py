"""Resolve a VPN provider by name (the ``vpn_provider`` config value).

Mullvad is the recommended default; later phases register a generic
WireGuard (bring-your-own config) provider and a custom-command provider
so any VPN can be used. Unknown names raise :class:`UnknownVpnProvider`
with the list of known providers so the wizard / CLI can guide the user
to a valid value rather than failing opaquely at bring-up time.

:func:`provider_capability` reports, per provider and platform, whether the
route is supported, whether it is usable right now, and a stable reason code.
It never starts a process. Native Windows ruling for this release: Tor is the
supported private route; ``mullvad`` and ``wireguard`` are
``supported=False`` with ``not-ported-on-windows`` (their tunnel services need
administrative installation and a separately validated route); ``custom`` is
supported only when every configured executable resolves to a validated
``.exe``. Wizard presentation of these values is a separate component.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable
from typing import NamedTuple

from ..._policy_types import PolicyMode
from .._exceptions import BringupFailed, UnknownVpnProvider
from .._windows_exec import ExecutableRefused, ResolvedExecutable
from ..guidance import MACOS_MULLVAD_APP_CLI
from ..paths.vpn import NOT_PORTED_ON_WINDOWS
from .base import VpnProvider
from .custom import CustomCommandProvider, resolve_windows_commands
from .mullvad import MullvadProvider
from .wireguard import WireGuardProvider

__all__ = ["NOT_PORTED_ON_WINDOWS", "ProviderCapability", "build_provider", "known_providers", "provider_capability"]


class ProviderCapability(NamedTuple):
    """``(supported, available, reason)``; ``reason`` is ``None`` when usable."""

    supported: bool
    available: bool
    reason: str | None


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


def provider_capability(
    name: str,
    *,
    policy_mode: PolicyMode = "off",
    wireguard_config_path: str | None = None,
    custom_up_cmd: tuple[str, ...] = (),
    custom_down_cmd: tuple[str, ...] = (),
    custom_health_cmd: tuple[str, ...] | None = None,
    platform: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    exists: Callable[[str], bool] = os.path.exists,
    windows_resolver: Callable[[str], ResolvedExecutable] | None = None,
) -> ProviderCapability:
    """Explicit per-provider capability; never starts a process.

    Windows custom executables are resolved and classified exactly as the
    provider will run them. An untrusted image is unavailable under strict
    policy and available with the ``executable-untrusted-location`` reason
    under lenient/off (the provider warns when it runs it). Unknown names
    raise :class:`UnknownVpnProvider`.
    """
    if name not in _KNOWN:
        known = ", ".join(_KNOWN)
        raise UnknownVpnProvider(f"unknown VPN provider {name!r}; known providers: {known}")
    if (platform or sys.platform) == "win32":
        return _windows_capability(
            name,
            policy_mode=policy_mode,
            commands=(custom_up_cmd, custom_down_cmd, custom_health_cmd),
            resolver=windows_resolver,
        )
    return _posix_capability(
        name,
        platform=platform or sys.platform,
        wireguard_config_path=wireguard_config_path,
        custom_up_cmd=custom_up_cmd,
        which=which,
        exists=exists,
    )


def _windows_capability(
    name: str,
    *,
    policy_mode: PolicyMode,
    commands: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...] | None],
    resolver: Callable[[str], ResolvedExecutable] | None,
) -> ProviderCapability:
    if name != "custom":
        return ProviderCapability(False, False, NOT_PORTED_ON_WINDOWS)
    up_cmd, down_cmd, health_cmd = commands
    if not up_cmd:
        return ProviderCapability(True, False, "custom-command-not-configured")
    try:
        resolved = resolve_windows_commands(up_cmd, down_cmd, health_cmd, resolver=resolver)
    except ExecutableRefused as refusal:
        return ProviderCapability(True, False, refusal.reason)
    except BringupFailed:
        return ProviderCapability(True, False, "custom-command-not-configured")
    if any(image.trust == "untrusted" for image in resolved.images):
        return ProviderCapability(True, policy_mode != "strict", "executable-untrusted-location")
    return ProviderCapability(True, True, None)


def _posix_capability(
    name: str,
    *,
    platform: str,
    wireguard_config_path: str | None,
    custom_up_cmd: tuple[str, ...],
    which: Callable[[str], str | None],
    exists: Callable[[str], bool],
) -> ProviderCapability:
    if name == "mullvad":
        installed = which("mullvad") is not None or (platform == "darwin" and exists(MACOS_MULLVAD_APP_CLI))
        return ProviderCapability(True, installed, None if installed else "not-installed")
    if name == "wireguard":
        if which("wg-quick") is None:
            return ProviderCapability(True, False, "not-installed")
        if not wireguard_config_path or not exists(wireguard_config_path):
            return ProviderCapability(True, False, "not-configured")
        return ProviderCapability(True, True, None)
    if not custom_up_cmd:
        return ProviderCapability(True, False, "custom-command-not-configured")
    binary = custom_up_cmd[0]
    installed = which(binary) is not None or (os.path.sep in binary and exists(binary))
    return ProviderCapability(True, installed, None if installed else "not-installed")
