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
from typing import Any, Final, Literal, Protocol

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
    can replace the global without surface changes. PR2 added
    :meth:`stop` and :meth:`is_dropped` so the hooks layer can route
    ``on_session_end`` tear-down and ``pre_tool_call`` strict-mode
    refusals through ``api`` instead of importing the concrete class.
    The M9 liveness worker sets ``is_dropped`` after two consecutive
    health failures; ``hooks.pre_tool_call`` reads it.
    """

    def use(self, path: str) -> None: ...

    def status(self) -> NetworkStatus: ...

    def health(self) -> bool: ...

    def stop(self) -> None: ...

    def is_dropped(self) -> bool: ...

    # ``PolicyMode`` Literal lives in :mod:`.runtime` to avoid an
    # import cycle; ``str`` here keeps the Protocol decoupled. The
    # concrete runtime narrows at the call site.
    def update_policy_mode(self, policy_mode: Any) -> None: ...

    def set_isolation_token(self, token: str | None) -> None: ...


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
    targets are Cloudflare's anycast resolvers (IPv4 ``1.1.1.1`` and
    IPv6 ``2606:4700:4700::1111``) on port 53; numeric literals so the
    probe never triggers a DNS lookup, even on captive portals.

    Both families are probed and ANY success counts as reachable
    (security review H3): an IPv4-only probe reports "isolated" on a
    dual-stack host whose IPv4 is down but whose IPv6 still routes,
    which would leak the all-clear to the keyvault Seed-Phrase blackout
    while the host can still egress over IPv6.

    PR1 ships this default; Phase 4 :mod:`keyvault.network_fallback` may
    swap it with an OS-API probe (TODO §4.1 L397).
    """
    targets = (
        (socket.AF_INET, ("1.1.1.1", 53)),
        (socket.AF_INET6, ("2606:4700:4700::1111", 53)),
    )
    for family, addr in targets:
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            try:
                sock.settimeout(0.5)
                sock.connect(addr)
            finally:
                sock.close()
        except OSError:
            continue  # this family has no route; try the next
        return True  # any family reachable ⇒ host is NOT isolated
    return False


def stop(*, runtime: Runtime | None = None) -> None:
    """Tear down the active path and stop the liveness worker.

    Safe to call when no runtime is registered (no-op) - the hooks
    layer invokes this from ``on_session_end`` and the session may
    have ended without ``register()`` ever running (defensive idempotence).
    """
    rt = runtime if runtime is not None else _RUNTIME
    if rt is None:
        return
    rt.stop()


def update_policy_mode(policy_mode: str, *, runtime: Runtime | None = None) -> None:
    """Refresh the runtime's policy mode (Codex r9-P1-B, 2026-05-14).

    Called by ``hooks.on_session_start`` so disk-state policy changes
    made after ``register()`` reach the runtime before the next
    ``api.use()``. No-op when no runtime is registered.
    """
    rt = runtime if runtime is not None else _RUNTIME
    if rt is None:
        return
    rt.update_policy_mode(policy_mode)


def set_isolation_token(token: str | None, *, runtime: Runtime | None = None) -> None:
    """Set the per-session Tor circuit-isolation token (v2-N1).

    ``hooks.on_session_start`` calls this with the Hermes ``session_id`` so
    each session rides its own Tor circuit (``IsolateSOCKSAuth``). No-op when
    no runtime is registered, mirroring :func:`update_policy_mode`.
    """
    rt = runtime if runtime is not None else _RUNTIME
    if rt is None:
        return
    rt.set_isolation_token(token)


def is_dropped(*, runtime: Runtime | None = None) -> bool:
    """Return ``True`` if the M9 liveness worker flagged a path drop.

    Returns ``False`` when no runtime is registered - the hooks layer
    treats "no runtime" as "no drop to react to", deferring the decision
    to whichever sibling plugin (e.g. ``privacy_check``) is actually
    enforcing strict policy.
    """
    rt = runtime if runtime is not None else _RUNTIME
    if rt is None:
        return False
    return rt.is_dropped()


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
