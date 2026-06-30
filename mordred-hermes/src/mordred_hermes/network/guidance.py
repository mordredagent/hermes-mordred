"""User-facing guidance for network-path external dependencies.

Mordred intentionally does not install Tor or Mullvad for the user: Tor is
an OS package/daemon, and Mullvad setup can mutate account and VPN state.
This module keeps the "what now?" text consistent across runtime failures
and the wizard CLI.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

MACOS_MULLVAD_APP_CLI = "/Applications/Mullvad VPN.app/Contents/Resources/mullvad"


def tor_install_guidance(*, tor_binary: str = "tor") -> str:
    """Return a concise next-step guide for a missing Tor executable."""
    return (
        "Install Tor and make sure the configured binary is executable. "
        "macOS: `brew install tor`; Debian/Ubuntu: `sudo apt-get install tor`. "
        f"If Tor is already installed elsewhere, rerun "
        f"`hermes-mordred network init --path tor --tor-binary /path/to/tor` "
        f"(current setting: `{tor_binary}`)."
    )


def mullvad_install_guidance() -> str:
    """Return a concise next-step guide for a missing Mullvad CLI."""
    return (
        "Install the official Mullvad VPN app/CLI, log in with "
        "`mullvad account login`, and make sure `mullvad` is on PATH. "
        f"On macOS Mordred also checks `{MACOS_MULLVAD_APP_CLI}`. "
        "Then rerun `hermes-mordred network init --path vpn` or switch to "
        "`tor` / `clearnet` with `hermes-mordred network use <path>`."
    )


def custom_vpn_install_guidance(up_cmd: tuple[str, ...]) -> str:
    """Return a next-step guide when the custom provider's CLI is missing."""
    if not up_cmd:
        return (
            "No connect command is configured for the custom VPN provider. Set "
            "`plugins.mordred_network.custom_up_cmd` (e.g. `[expressvpnctl, connect]`) "
            "or rerun `hermes-mordred network init --path vpn`."
        )
    binary = up_cmd[0]
    return (
        f"Install the VPN's CLI so `{binary}` is on PATH (or give an absolute path in "
        "`plugins.mordred_network.custom_up_cmd`), then rerun "
        "`hermes-mordred network init --path vpn` or switch to `tor` / `clearnet` with "
        "`hermes-mordred network use <path>`."
    )


def wireguard_config_guidance(config_path: str) -> str:
    """Return a next-step guide when the WireGuard `.conf` is missing."""
    current = config_path or "(unset)"
    return (
        "Point `plugins.mordred_network.wireguard_config_path` at an existing WireGuard "
        f"`.conf` (current: `{current}`) — export one from your VPN's portal — then rerun "
        "`hermes-mordred network init --path vpn` or switch to `tor` / `clearnet` with "
        "`hermes-mordred network use <path>`."
    )


def is_tor_binary_available(tor_binary: str) -> bool:
    """Best-effort executable lookup for a configured Tor binary."""
    if not tor_binary:
        return False
    if "/" in tor_binary:
        return Path(tor_binary).exists()
    return shutil.which(tor_binary) is not None


def is_mullvad_cli_available() -> bool:
    """Best-effort lookup for the Mullvad CLI."""
    return shutil.which("mullvad") is not None or Path(MACOS_MULLVAD_APP_CLI).exists()


def is_custom_vpn_command_available(up_cmd: tuple[str, ...]) -> bool:
    """Best-effort lookup for the custom provider's connect command.

    Mirrors :meth:`CustomCommandProvider.detect_cli`: a bare name is resolved
    on PATH; a path containing a separator must exist on disk.
    """
    if not up_cmd:
        return False
    binary = up_cmd[0]
    if shutil.which(binary) is not None:
        return True
    return os.path.sep in binary and Path(binary).exists()


def is_wireguard_config_available(config_path: str) -> bool:
    """True when the configured WireGuard `.conf` exists on disk."""
    return bool(config_path) and Path(config_path).exists()


def dependency_warning(
    path: str,
    *,
    tor_binary: str = "tor",
    vpn_provider: str = "mullvad",
    custom_up_cmd: tuple[str, ...] = (),
    wireguard_config_path: str = "",
) -> str | None:
    """Return a warning for a selected path whose external dependency is absent.

    The `vpn` route dispatches on ``vpn_provider`` so the precheck matches the
    provider actually selected — the custom provider's own CLI, a WireGuard
    `.conf`, or the Mullvad CLI — instead of always assuming Mullvad.
    """
    if path == "tor" and not is_tor_binary_available(tor_binary):
        return (
            "[warning] The `tor` route is selected, but Tor is not available yet, "
            "so it cannot carry traffic — your connection stays on the current route "
            f"until you install it. {tor_install_guidance(tor_binary=tor_binary)}"
        )
    if path == "vpn":
        return _vpn_dependency_warning(
            vpn_provider,
            custom_up_cmd=custom_up_cmd,
            wireguard_config_path=wireguard_config_path,
        )
    return None


def _vpn_dependency_warning(
    provider: str,
    *,
    custom_up_cmd: tuple[str, ...],
    wireguard_config_path: str,
) -> str | None:
    """Provider-specific dependency warning for the `vpn` route."""
    if provider == "custom":
        if is_custom_vpn_command_available(custom_up_cmd):
            return None
        binary = f"`{custom_up_cmd[0]}`" if custom_up_cmd else "its connect command"
        return (
            f"[warning] The `vpn` route is selected with the custom provider, but {binary} "
            "is not available yet, so it cannot carry traffic — your connection stays on the "
            f"current route until you install it. {custom_vpn_install_guidance(custom_up_cmd)}"
        )
    if provider == "wireguard":
        if is_wireguard_config_available(wireguard_config_path):
            return None
        return (
            "[warning] The `vpn` route is selected with the wireguard provider, but its "
            "WireGuard config is not available yet, so it cannot carry traffic — your "
            "connection stays on the current route until you provide it. "
            f"{wireguard_config_guidance(wireguard_config_path)}"
        )
    if not is_mullvad_cli_available():
        return (
            "[warning] The `vpn` route is selected, but the Mullvad CLI is not available yet, "
            "so it cannot carry traffic — your connection stays on the current route "
            f"until you install it. {mullvad_install_guidance()}"
        )
    return None


__all__ = [
    "MACOS_MULLVAD_APP_CLI",
    "custom_vpn_install_guidance",
    "dependency_warning",
    "is_custom_vpn_command_available",
    "is_mullvad_cli_available",
    "is_tor_binary_available",
    "is_wireguard_config_available",
    "mullvad_install_guidance",
    "tor_install_guidance",
    "wireguard_config_guidance",
]
