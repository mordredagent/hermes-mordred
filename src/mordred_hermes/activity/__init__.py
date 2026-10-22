"""Mordred ``activity`` component: browser activity capture into the encrypted ``mordred.db``, used by Hermes.

The operator collector (and the paired extension) deliver activity batches to
the extension server's receiver (:mod:`.ingest`). Hermes uses the recorded
history directly (:mod:`.history`): :func:`register` wires

- the ``transform_tool_result`` and ``pre_llm_call`` hooks
  (:func:`.hooks_history.register_hooks`), which add a site's history to
  browser navigation results and the user's own relevant task and correction
  texts (with metadata) to a turn;
- the ``mordred_browser_history`` / ``mordred_browser_history_episode`` lookup
  tools and the ``browser-history`` skill (:func:`.tools.register_tools`);
- the ``post_tool_call`` and a second ``pre_llm_call`` hook
  (:func:`.capture_hermes.register_hooks`), which record Hermes's own browser
  calls and the user's ``correct:`` messages through the receiver. They are
  registered after the history hooks, so a turn's history block is read before
  that turn's correction is stored.

Registration reads no configuration and never opens the store; every surface
checks ``plugins.mordred_activity`` (``enabled`` and the master switch
``history_enabled``; capture also ``collection_enabled``) and the protection
gate when it runs. The store, the
gate, pairing and the CLI are imported lazily by their own entry points, so
importing this package stays cheap at plugin discovery.
"""

from __future__ import annotations

from typing import Any

__all__ = ["register"]


def register(ctx: Any) -> None:
    """Register the history and capture hooks, tools and skill; never reads configuration or opens the store."""
    from . import capture_hermes
    from .hooks_history import register_hooks
    from .tools import register_tools

    register_hooks(ctx)
    register_tools(ctx)
    capture_hermes.register_hooks(ctx)
