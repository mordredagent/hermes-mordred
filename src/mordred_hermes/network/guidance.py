"""User-facing guidance for network-path external dependencies.

Mordred intentionally does not install Tor or Mullvad for the user: Tor is
an OS package/daemon, and Mullvad setup can mutate account and VPN state.
This module keeps the "what now?" text consistent across runtime failures
and the wizard CLI.
"""

from __future__ import annotations

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
        f"(current setting: {tor_binary!r})."
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


def dependency_warning(path: str, *, tor_binary: str = "tor") -> str | None:
    """Return a warning for a selected path whose external dependency is absent."""
    if path == "tor" and not is_tor_binary_available(tor_binary):
        return f"[warning] Tor is not available yet. {tor_install_guidance(tor_binary=tor_binary)}"
    if path == "vpn" and not is_mullvad_cli_available():
        return f"[warning] Mullvad CLI is not available yet. {mullvad_install_guidance()}"
    return None


__all__ = [
    "MACOS_MULLVAD_APP_CLI",
    "dependency_warning",
    "is_mullvad_cli_available",
    "is_tor_binary_available",
    "mullvad_install_guidance",
    "tor_install_guidance",
]
