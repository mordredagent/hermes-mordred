"""Generic WireGuard provider — bring your own ``.conf``.

Drives ``wg-quick up/down`` on a user-supplied WireGuard configuration.
This is how "any VPN" is satisfied for the large class of services that
let you export a WireGuard config — Proton VPN, IVPN, Windscribe, a
self-hosted peer, etc.: point ``wireguard_config_path`` at the ``.conf``
and Mordred brings it up.

Capabilities are conservative: generic ``wg-quick`` has no built-in
kill-switch (that needs host firewall rules Mordred does not manage) and
Mordred cannot verify the config forces in-tunnel DNS, so both flags are
``False``. The runtime's strict-mode gate therefore refuses this provider
under ``strict`` policy — it is meant for ``lenient`` / ``off`` use, where
any VPN is fine. Mullvad remains the strict-capable default.

Platform: macOS + Linux (wherever ``wg-quick`` runs). Subprocess I/O goes
through the injectable runner so tests never touch a real interface.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .._exceptions import BringupFailed
from ..paths.vpn import DEFAULT_MAX_HANDSHAKE_AGE_SECONDS, parse_handshake_age
from .base import DEFAULT_RUNNER, PolicyMode, SubprocessRunner, VpnCapabilities

__all__ = ["WireGuardHandle", "WireGuardProvider", "wireguard_install_guidance"]

_LOG = logging.getLogger("mordred.network.vpn")
DEFAULT_COMMAND_TIMEOUT: Final[float] = 30.0


def wireguard_install_guidance() -> str:
    """Concise next-step guide for a missing ``wg-quick`` / config."""
    return (
        "Install the WireGuard tools (`wg-quick` + `wg`). macOS: "
        "`brew install wireguard-tools`; Debian/Ubuntu: "
        "`sudo apt-get install wireguard-tools`. Export a WireGuard config "
        "from your VPN (e.g. Proton VPN, IVPN), then set "
        "`plugins.mordred_network.wireguard_config_path` to its `.conf` path."
    )


@dataclass(frozen=True, slots=True)
class WireGuardHandle:
    """What we brought up. ``wg-quick down`` needs the same config path."""

    wg_quick_path: str
    config_path: str


class WireGuardProvider:
    """Provider driving ``wg-quick`` against a bring-your-own config."""

    name = "wireguard"
    capabilities = VpnCapabilities(killswitch=False, dns_leak_safe=False)

    def __init__(
        self,
        *,
        config_path: str | None,
        exists: Callable[[str], bool] = os.path.exists,
    ) -> None:
        # ``exists`` is injectable so tests can assert config-validation
        # without touching the filesystem.
        self._config_path = config_path
        self._exists = exists

    def detect_cli(self, *, which: Callable[[str], str | None] = shutil.which) -> str:
        path = which("wg-quick")
        if not path:
            raise BringupFailed(f"wg-quick not installed. {wireguard_install_guidance()}")
        return path

    def bring_up(
        self,
        *,
        cli_path: str,
        region: str,
        policy_mode: PolicyMode,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> WireGuardHandle:
        # The WireGuard config pins the relay; the strict kill-switch gate
        # is enforced upstream in the runtime. region / policy_mode do not
        # apply here.
        del region, policy_mode
        if not self._config_path:
            raise BringupFailed(
                f"wireguard provider selected but no config path is set. {wireguard_install_guidance()}"
            )
        if not self._exists(self._config_path):
            raise BringupFailed(f"wireguard config not found: {self._config_path!r}. {wireguard_install_guidance()}")
        try:
            result = runner(
                (cli_path, "up", self._config_path),
                timeout=DEFAULT_COMMAND_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BringupFailed(f"`wg-quick up {self._config_path}` failed or timed out: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise BringupFailed(f"`wg-quick up {self._config_path}` failed (rc={result.returncode}): {detail!r}")
        return WireGuardHandle(wg_quick_path=cli_path, config_path=self._config_path)

    def wait_connected(self, *, cli_path: str, runner: SubprocessRunner = DEFAULT_RUNNER) -> None:
        # ``wg-quick up`` is synchronous: once bring_up returns 0 the
        # interface is configured. Handshake liveness is the health
        # probe's job, mirroring the Mullvad path.
        del cli_path, runner

    def disconnect(
        self,
        handle: WireGuardHandle,
        *,
        preserve_lockdown: bool = True,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> None:
        # No kill-switch to preserve for generic WireGuard.
        del preserve_lockdown
        try:
            result = runner(
                (handle.wg_quick_path, "down", handle.config_path),
                timeout=DEFAULT_COMMAND_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _LOG.warning("`wg-quick down %s` failed or timed out: %s", handle.config_path, exc)
            return
        if result.returncode != 0:
            # Teardown failures must not raise (callers swallow-and-continue),
            # but a silently-still-up tunnel is worth surfacing.
            _LOG.warning("`wg-quick down %s` failed (rc=%s)", handle.config_path, result.returncode)

    def health(self, handle: WireGuardHandle, *, runner: SubprocessRunner = DEFAULT_RUNNER) -> bool:
        # Probe the specific interface we brought up (``wg show <iface>``),
        # not all interfaces — otherwise an unrelated WireGuard tunnel on the
        # host would mask our tunnel dropping. wg-quick names the interface
        # after the config basename (``/etc/wireguard/wg0.conf`` -> ``wg0``).
        # Any subprocess failure (incl. ``wg`` missing) is coerced to
        # unhealthy so the liveness worker records the path as down.
        interface = Path(handle.config_path).stem
        try:
            result = runner(
                ("wg", "show", interface),
                timeout=DEFAULT_COMMAND_TIMEOUT,
            )
        except (FileNotFoundError, PermissionError, subprocess.SubprocessError, OSError):
            return False
        if result.returncode != 0:
            return False
        age = parse_handshake_age(result.stdout or "")
        if age is None:
            return False
        return age <= DEFAULT_MAX_HANDSHAKE_AGE_SECONDS
