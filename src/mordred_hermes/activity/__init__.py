"""Mordred ``activity`` component: browser activity capture and conditional learning.

``register`` wires three things and nothing else:

- the lifecycle observation hooks and the review auxiliary task
  (:func:`boundary.register_hooks`): the hooks copy identifiers into a bounded
  in-process registry and return — they never open the store, read history,
  start a thread or call a model;
- the two recall tools over admitted lessons and the ``activity-recall`` /
  ``activity-review`` skills (:func:`tools.register_tools`).

Store, ingestion, review and CLI code are imported lazily by their own entry
points; importing this package stays cheap at plugin discovery.
"""

from __future__ import annotations

from typing import Any

__all__ = ["register"]


def register(ctx: Any) -> None:
    from .boundary import register_hooks
    from .tools import register_tools

    register_hooks(ctx)
    register_tools(ctx)
