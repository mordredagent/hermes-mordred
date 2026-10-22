"""Mordred ``activity`` component: browser activity capture into the encrypted ``mordred.db``, used by Hermes.

The operator collector (and the paired extension) deliver activity batches to
the extension server's receiver (:mod:`.ingest`). Hermes uses the recorded
history directly (:mod:`.history`): :func:`register` wires

- the ``transform_tool_result`` and ``pre_llm_call`` hooks
  (:func:`.hooks_history.register_hooks`), which add a site's history to
  browser navigation results and relevant human-authored history to a turn;
- the ``mordred_browser_history`` / ``mordred_browser_history_episode`` lookup
  tools and the ``browser-history`` skill (:func:`.tools.register_tools`).

Registration reads no configuration and never opens the store; every surface
checks ``plugins.mordred_activity`` (``enabled`` and the master switch
``history_enabled``) and the protection gate when it runs. The store, the
gate, pairing and the CLI are imported lazily by their own entry points, so
importing this package stays cheap at plugin discovery.
"""

from __future__ import annotations

from typing import Any

__all__ = ["register"]


def register(ctx: Any) -> None:
    """Register the history hooks, tools and skill; never reads configuration or opens the store."""
    from .hooks_history import register_hooks
    from .tools import register_tools

    register_hooks(ctx)
    register_tools(ctx)
