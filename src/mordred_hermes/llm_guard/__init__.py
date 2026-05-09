"""mordred_llm_guard — strict-mode local LLM enforcement.

Phase 0 scaffold: register() is a no-op stub. Phase 2.1 will wire:
- mordred-local synthetic provider adapter
- pre_llm_call hook (override to local endpoint per policy)
- on_session_start hook (harness-primary detection)
"""

from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point. Phase 0 stub — no provider/hooks registered yet."""
    return None
