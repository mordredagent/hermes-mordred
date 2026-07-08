"""Provider abstraction for the ``"vpn"`` network path.

The ``"vpn"`` route stays a single path; the *provider* behind it is
selectable so Mordred can drive Mullvad (the recommended default), a
bring-your-own WireGuard config, or any VPN exposing an up/down/health
command — not just Mullvad.

The runtime treats a provider as five operations plus a capability
descriptor. The signatures deliberately mirror the original
:mod:`mordred_hermes.network.paths.vpn` module functions so converting
the runtime to this seam is behaviour-preserving for Mullvad. Providers
that do not have a Mullvad-style CLI (WireGuard, custom) accept and
ignore the Mullvad-shaped ``region`` / ``cli_path`` arguments and resolve
their own configuration bound at construction time.

:class:`VpnCapabilities` is the contract the runtime's strict-mode gate
reads: a provider that cannot guarantee a kill-switch / in-tunnel DNS is
refused under ``strict`` policy (fail-closed) rather than silently
running without leak protection.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ..._policy_types import PolicyMode
from ..paths.vpn import DEFAULT_RUNNER, SubprocessRunner

#: Re-exported so providers and the runtime share one runner type.
__all__ = ["DEFAULT_RUNNER", "PolicyMode", "SubprocessRunner", "VpnCapabilities", "VpnProvider"]


@dataclass(frozen=True, slots=True)
class VpnCapabilities:
    """What strict-mode guarantees a provider can make.

    ``killswitch`` — Mordred can ensure all traffic is blocked when the
    tunnel drops (Mullvad ``lockdown-mode``; a firewall-backed WireGuard
    setup). ``dns_leak_safe`` — the provider forces DNS resolution inside
    the tunnel. Both are ``True`` only when Mordred itself can drive and
    verify the behaviour, not when it merely trusts a vendor app.
    """

    killswitch: bool
    dns_leak_safe: bool


class VpnProvider(Protocol):
    """The five operations + capabilities the runtime needs from a VPN.

    Implementations live in sibling modules (``mullvad``, ``wireguard``,
    ``custom``) and are resolved by name via
    :func:`mordred_hermes.network.vpn_providers.registry.build_provider`.
    """

    #: Stable identifier persisted to ``config.yaml`` (``vpn_provider``).
    name: str
    #: Strict-mode guarantees; read by the runtime's kill-switch gate.
    capabilities: VpnCapabilities

    def detect_cli(self, *, which: Callable[[str], str | None] = shutil.which) -> str:
        """Resolve the executable / config the provider needs, or raise
        :class:`mordred_hermes.network._exceptions.BringupFailed`."""
        ...

    def bring_up(
        self,
        *,
        cli_path: str,
        region: str,
        policy_mode: PolicyMode,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> Any:
        """Initiate the tunnel and return an opaque handle."""
        ...

    def wait_connected(self, *, cli_path: str, runner: SubprocessRunner = DEFAULT_RUNNER) -> None:
        """Block until the tunnel is up, or raise ``BringupFailed`` on timeout."""
        ...

    def disconnect(
        self,
        handle: Any,
        *,
        preserve_lockdown: bool = True,
        runner: SubprocessRunner = DEFAULT_RUNNER,
    ) -> None:
        """Tear the tunnel down. ``preserve_lockdown`` keeps a kill-switch
        engaged across the teardown when the provider has one."""
        ...

    def health(self, handle: Any, *, runner: SubprocessRunner = DEFAULT_RUNNER) -> bool:
        """Return ``True`` iff the tunnel is currently live."""
        ...
