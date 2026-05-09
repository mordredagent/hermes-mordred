"""mordred_privacy_check — skill metadata enforcement and audit logging.

Phase 0 scaffold: register() is a no-op stub. Phase 1.1 will wire:
- pre_tool_call hook (per-skill / generic allowlist)
- on_session_start hook (policy load + sibling-disabled detection, H3 Path B)
- audit logger (~/.hermes/mordred/audit.log)
"""

from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point. Phase 0 stub — no hooks registered yet."""
    return None
