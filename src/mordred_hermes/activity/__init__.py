"""Mordred ``activity`` component: browser activity capture into the encrypted ``mordred.db``.

The operator collector (and the paired extension) deliver activity batches to
the extension server's receiver (:mod:`.ingest`); the store, the protection
gate, pairing and the CLI are imported lazily by their own entry points, so
importing this package stays cheap at plugin discovery.

:func:`register` is deliberately a no-op: the component keeps its place in the
plugin's fixed wiring order, but it registers no hook, tool, skill or
auxiliary task. Hermes-side use of the recorded history arrives in a later
phase (``docs/superpowers/specs/2026-10-22-browser-history-for-hermes-design.md``).
"""

from __future__ import annotations

from typing import Any

__all__ = ["register"]


def register(ctx: Any) -> None:
    """Register nothing (see the module docstring); never opens the store."""
    del ctx
