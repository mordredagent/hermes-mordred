"""Custom-command VPN provider — the "any VPN" escape hatch.

Drives user-configured up / down / health commands so a VPN that ships
only its own CLI (ExpressVPN's ``expressvpnctl connect``, NordVPN's
``nordvpn connect``, Surfshark, …) can be used without a dedicated
provider module.

Security model (this provider executes operator-supplied commands):

- Commands are **argv lists**, executed through the shared runner which
  calls ``subprocess.run(list(argv))`` with **no** ``shell=True``. There
  is no shell, so no glob / pipe / ``$()`` interpretation and no
  shell-injection surface.
- The argv come only from ``plugins.mordred_network.custom_*`` in
  ``config.yaml`` — operator-controlled configuration, never network- or
  agent-derived input.
- ``capabilities.killswitch`` is ``False``: Mordred cannot verify a
  third-party CLI actually blocks traffic on drop, so the runtime's
  strict-mode gate refuses this provider. It is for ``lenient`` / ``off``
  use. (A self-declared kill-switch flag is intentionally not offered
  here; promoting an unverifiable claim to a strict guarantee would
  defeat the fail-closed design.)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from .._exceptions import BringupFailed
from .base import DEFAULT_RUNNER, PolicyMode, SubprocessRunner, VpnCapabilities

__all__ = ["CustomCommandProvider", "CustomHandle"]

_LOG = logging.getLogger("mordred.network.vpn")

# Operator-provided connect commands may legitimately take longer than status
# probes, but none may hold Runtime's lifecycle serialization lock forever.
DEFAULT_UP_TIMEOUT: Final[float] = 60.0
DEFAULT_COMMAND_TIMEOUT: Final[float] = 15.0


def _command_summary(argv: tuple[str, ...]) -> str:
    """Identify a configured command without exposing its arguments."""
    if not argv:
        return "<empty command>"
    executable = os.path.basename(argv[0]) or "<configured executable>"
    executable = "".join(char if ord(char) >= 0x20 and ord(char) != 0x7F else "?" for char in executable)[:64]
    return f"{executable!r} with {max(0, len(argv) - 1)} argument(s)"


@dataclass(frozen=True, slots=True)
class CustomHandle:
    """Commands needed to tear down / probe the tunnel we brought up."""

    down_cmd: tuple[str, ...]
    health_cmd: tuple[str, ...] | None


class CustomCommandProvider:
    """Provider running operator-configured up/down/health argv."""

    name = "custom"
    capabilities = VpnCapabilities(killswitch=False, dns_leak_safe=False)

    def __init__(
        self,
        *,
        up_cmd: tuple[str, ...],
        down_cmd: tuple[str, ...],
        health_cmd: tuple[str, ...] | None = None,
    ) -> None:
        self._up_cmd = tuple(up_cmd)
        self._down_cmd = tuple(down_cmd)
        self._health_cmd = tuple(health_cmd) if health_cmd else None

    def detect_cli(self, *, which: Callable[[str], str | None] = shutil.which) -> str:
        if not self._up_cmd:
            raise BringupFailed(
                "custom vpn provider selected but no up command configured; "
                "set plugins.mordred_network.custom_up_cmd (e.g. [expressvpnctl, connect])."
            )
        binary = self._up_cmd[0]
        resolved = which(binary)
        if resolved:
            return resolved
        # Allow an explicit path that exists even when not on PATH.
        if os.path.sep in binary and os.path.exists(binary):
            return binary
        raise BringupFailed(
            f"custom vpn executable {_command_summary(self._up_cmd)} was not found. "
            "Install the VPN's CLI or fix custom_up_cmd."
        )

    def bring_up(
        self,
        *,
        cli_path: str,
        region: str,
        policy_mode: PolicyMode,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> CustomHandle:
        # The configured command encodes its own relay / options; the
        # strict kill-switch gate is enforced upstream in the runtime.
        del cli_path, region, policy_mode
        if not self._up_cmd:
            raise BringupFailed("custom vpn provider selected but no up command configured; set custom_up_cmd.")
        try:
            result = runner(self._up_cmd, timeout=DEFAULT_UP_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BringupFailed(
                f"custom vpn up command {_command_summary(self._up_cmd)} failed or timed out ({type(exc).__name__})"
            ) from exc
        if result.returncode != 0:
            raise BringupFailed(
                f"custom vpn up command {_command_summary(self._up_cmd)} failed (rc={result.returncode})"
            )
        return CustomHandle(down_cmd=self._down_cmd, health_cmd=self._health_cmd)

    def wait_connected(self, *, cli_path: str, runner: SubprocessRunner = DEFAULT_RUNNER) -> None:
        # The up command is expected to return once connected; there is no
        # generic readiness signal to poll for an arbitrary CLI.
        del cli_path, runner

    def disconnect(
        self,
        handle: CustomHandle,
        *,
        preserve_lockdown: bool = True,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> None:
        del preserve_lockdown  # no Mordred-managed kill-switch to preserve
        if handle.down_cmd:
            try:
                result = runner(
                    handle.down_cmd,
                    timeout=DEFAULT_COMMAND_TIMEOUT,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                _LOG.warning(
                    "custom vpn down command %s failed or timed out (%s)",
                    _command_summary(handle.down_cmd),
                    type(exc).__name__,
                )
                return
            if result.returncode != 0:
                # Don't raise on teardown; surface a silently-still-up tunnel.
                _LOG.warning(
                    "custom vpn down command %s failed (rc=%s)",
                    _command_summary(handle.down_cmd),
                    result.returncode,
                )

    def health(self, handle: CustomHandle, *, runner: SubprocessRunner = DEFAULT_RUNNER) -> bool:
        # With no probe configured we cannot observe a drop, so we report
        # healthy rather than flapping the path down on every liveness pass.
        if not handle.health_cmd:
            return True
        try:
            result = runner(
                handle.health_cmd,
                timeout=DEFAULT_COMMAND_TIMEOUT,
            )
        except (FileNotFoundError, PermissionError, subprocess.SubprocessError, OSError):
            return False
        return result.returncode == 0
