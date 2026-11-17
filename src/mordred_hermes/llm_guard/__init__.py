"""mordred_llm_guard — local LLM enforcement.

The Hermes plugin component that registers the ``mordred-local`` provider and
the session / per-request provider enforcement hooks. The implementation
lives in :mod:`._registration`; this package module only re-exports the entry
point. Submodules (``enforce``, ``harness_detect``, ``local_adapter``,
``auxiliary_guard``, ...) are imported the usual way.
"""

from __future__ import annotations

from ._registration import (
    register,
)

__all__ = [
    "register",
]
