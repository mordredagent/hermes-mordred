"""Public Python API for the mordred_network plugin.

PR1 defines the surface and the runtime :class:`~typing.Protocol`. PR2
will land the concrete :class:`mordred_hermes.network.runtime.Runtime`
singleton, register it via :func:`set_runtime`, and wire the lifecycle
hooks. Until then, callers pass a runtime explicitly through ``runtime=``.

Functions:

- :func:`use` — switch the active network path.
- :func:`status` — read the current state (active_path / ready / health).
- :func:`health` — synchronous liveness probe of the current path.
- :func:`blackout_assert` — raise if the host has network reachability.

The module is intentionally stateful (a module-level :data:`_RUNTIME`)
because Mordred plugins share a single Hermes process and
``mordred_keyvault`` needs to call :func:`blackout_assert` without
threading a runtime handle through its own API surface (TODO §4.1 L397).
Tests use :func:`reset_runtime_for_tests` to drop the registration.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from ._exceptions import BlackoutNotAsserted, MordredNetworkError, UnknownPath

ActivePath = Literal["tor", "vpn", "clearnet"]

_VALID_PATHS: Final[frozenset[str]] = frozenset({"tor", "vpn", "clearnet"})


@dataclass(frozen=True, slots=True)
class NetworkStatus:
    """Snapshot of the network path state.

    ``ready`` is ``True`` once bring-up has completed; ``last_health`` is
    the most recent liveness probe result (updated on every M9 worker
    pass in PR2).
    """

    active_path: str
    ready: bool
    last_health: bool


class Runtime(Protocol):
    """The concrete singleton implemented in PR2 ``runtime.py``.

    Kept narrow so PR1 tests can satisfy it with a tiny fake and PR2
    can replace the global without surface changes.
    """

    def use(self, path: str) -> None: ...

    def status(self) -> NetworkStatus: ...

    def health(self) -> bool: ...


_RUNTIME: Runtime | None = None


def set_runtime(runtime: Runtime) -> None:
    """Register the process-wide runtime. PR2's plugin ``register()`` calls this."""
    global _RUNTIME
    _RUNTIME = runtime


def reset_runtime_for_tests() -> None:
    """Clear the global runtime. Test-only.

    Production code should never call this — flipping the runtime mid-
    session would orphan a running subprocess.
    """
    global _RUNTIME
    _RUNTIME = None


def _resolve_runtime(runtime: Runtime | None) -> Runtime:
    rt = runtime if runtime is not None else _RUNTIME
    if rt is None:
        raise MordredNetworkError(
            "mordred_network runtime not registered; ensure the plugin's register() ran or pass runtime= explicitly"
        )
    return rt


def use(path: ActivePath, *, runtime: Runtime | None = None) -> None:
    """Switch the active path. Raises :class:`UnknownPath` for bad input."""
    if path not in _VALID_PATHS:
        raise UnknownPath(f"unknown network path: {path!r}")
    rt = _resolve_runtime(runtime)
    rt.use(path)


def status(*, runtime: Runtime | None = None) -> NetworkStatus:
    """Return the current path state."""
    return _resolve_runtime(runtime).status()


def health(*, runtime: Runtime | None = None) -> bool:
    """Run a synchronous liveness probe of the active path."""
    return _resolve_runtime(runtime).health()


def _default_probe() -> bool:
    """Probe outbound reachability via a non-blocking UDP socket connect.

    Returns ``True`` when ``socket.connect`` to a public IP succeeds —
    UDP ``connect`` is connection-less, so this measures routing
    reachability rather than performing an actual transmission. The
    default target is Cloudflare's anycast resolver (1.1.1.1:53) since
    it has no DNS leak even on captive portals.

    PR1 ships this default; Phase 4 :mod:`keyvault.network_fallback` may
    swap it with an OS-API probe (TODO §4.1 L397).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.5)
            sock.connect(("1.1.1.1", 53))
        finally:
            sock.close()
    except OSError:
        return False
    return True


def blackout_assert(*, probe: Callable[[], bool] | None = None) -> None:
    """Raise :class:`BlackoutNotAsserted` if the host is network-reachable.

    The probe returns ``True`` when *reachability* is detected. The
    inversion exists so the default UDP connect can be expressed as
    "succeeded → reachable".

    Phase 4 ``keyvault.seed_display`` calls this before unmasking a
    Seed Phrase to confirm the user pulled their Bluetooth, USB tether,
    and hotspot before requesting the display.
    """
    probe_fn = probe if probe is not None else _default_probe
    if probe_fn():
        raise BlackoutNotAsserted("network probe succeeded; expected an isolated host")
