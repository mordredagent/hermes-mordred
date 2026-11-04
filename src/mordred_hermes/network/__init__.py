"""mordred_network - Tor / VPN / Clearnet path management.

The Hermes plugin component for the process-wide Tor / VPN / clearnet route.
The implementation (runtime construction, hook wiring, config readers) lives
in :mod:`._registration`; this package module only re-exports the entry point
so the package namespace stays free of patchable implementation state.
Submodules (``api``, ``hooks``, ``runtime``, ``settings``, ``proxy_env``, ...)
are imported the usual way.
"""

from __future__ import annotations

from ._registration import (
    register,
)

__all__ = [
    "register",
]
