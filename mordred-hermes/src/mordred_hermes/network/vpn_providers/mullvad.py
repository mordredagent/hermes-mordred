"""Mullvad VPN provider — the recommended default.

Delegates every operation to the original
:mod:`mordred_hermes.network.paths.vpn` module so behaviour is identical
to the pre-provider runtime (a faithful refactor, not a rewrite).

Declares full strict-mode capabilities: Mordred drives
``mullvad lockdown-mode`` directly (a verifiable kill-switch) and the
Mullvad client forces in-tunnel DNS, so both guarantees hold. This is
why Mullvad — alone among providers — is allowed under ``strict`` policy
by the runtime's kill-switch gate.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable

from ..paths import vpn as _vpn
from .base import DEFAULT_RUNNER, PolicyMode, SubprocessRunner, VpnCapabilities

__all__ = ["MullvadProvider"]


class MullvadProvider:
    """Provider wrapping the official ``mullvad`` CLI (see ``paths.vpn``)."""

    name = "mullvad"
    capabilities = VpnCapabilities(killswitch=True, dns_leak_safe=True)

    def detect_cli(self, *, which: Callable[[str], str | None] = shutil.which) -> str:
        return _vpn.detect_cli(which=which)

    def bring_up(
        self,
        *,
        cli_path: str,
        region: str,
        policy_mode: PolicyMode,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> _vpn.MullvadHandle:
        return _vpn.bring_up(cli_path=cli_path, region=region, policy_mode=policy_mode, runner=runner)

    def wait_connected(self, *, cli_path: str, runner: SubprocessRunner = DEFAULT_RUNNER) -> None:
        _vpn.wait_connected(cli_path=cli_path, runner=runner)

    def disconnect(
        self,
        handle: _vpn.MullvadHandle,
        *,
        preserve_lockdown: bool = True,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> None:
        _vpn.disconnect(handle, preserve_lockdown=preserve_lockdown, runner=runner)

    def health(self, handle: _vpn.MullvadHandle, *, runner: SubprocessRunner = DEFAULT_RUNNER) -> bool:
        return _vpn.health(handle, runner=runner)
