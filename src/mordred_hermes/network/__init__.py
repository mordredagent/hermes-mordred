"""mordred_network — Tor / VPN / Clearnet path management.

Phase 0 scaffold: register() is a no-op stub. Phase 3.1 will wire:
- on_session_start / on_session_end (path bring-up / tear-down)
- pre_tool_call (origin_skill network_requirements check)
- internal API: use(path), status(), health(), blackout_assert()
"""

from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point. Phase 0 stub — no path manager registered yet."""
    return None
