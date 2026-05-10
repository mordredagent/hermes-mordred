"""Minimal typing surface for ``hermes_cli.plugins.PluginContext`` (wizard subset).

The wizard only calls ``register_cli_command`` to expose the
``hermes mordred ...`` subcommand tree. We declare a structural Protocol
covering only that one method — drift in Hermes's signature surfaces as
a mypy error here AND as an ``upstream-check.yml`` workflow alert.

Reference: ``hermes_cli/plugins.py:301`` (PluginContext.register_cli_command,
Hermes 0.11.0). Signature: ``(name, help, setup_fn, handler_fn=None,
description="")``.

Each plugin owns its own narrow Protocol — see
``privacy_check/_typing.py`` for the same rationale.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any, Protocol

# Hermes calls ``setup_fn(plugin_parser)`` where ``plugin_parser`` is the
# top-level argparse subparser created via ``subparsers.add_parser(name, ...)``.
# The setup_fn is responsible for adding sub-subparsers and using
# ``set_defaults(func=...)`` to wire dispatch.
SetupFn = Callable[[argparse.ArgumentParser], None]

# Optional fallback dispatch handler — called via ``set_defaults(func=...)``
# when setup_fn does not wire its own. Receives parsed args; returns
# anything (Hermes ignores). We keep wide arg/return types because each
# subcommand returns a different shape.
HandlerFn = Callable[[argparse.Namespace], Any]


class PluginContext(Protocol):
    """Subset of ``hermes_cli.plugins.PluginContext`` used by the wizard."""

    def register_cli_command(
        self,
        name: str,
        help: str,
        setup_fn: SetupFn,
        handler_fn: HandlerFn | None = None,
        description: str = "",
    ) -> None: ...
