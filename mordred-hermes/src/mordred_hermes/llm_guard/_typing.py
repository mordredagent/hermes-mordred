"""Minimal typing surface for ``hermes_cli.plugins.PluginContext``.

Hermes does not publish type stubs (see ``[[tool.mypy.overrides]]`` in
``pyproject.toml``), so we declare a structural ``Protocol`` covering only
the methods this plugin actually calls. Each plugin declares its own narrow
Protocol — do not promote to a shared module unless multiple plugins share
the same surface (mirror of ``privacy_check/_typing.py``).

Drift detection: if Hermes changes ``register_hook`` signature, the
``upstream-check.yml`` workflow flags it; mypy here will then fail because
the real ``ctx`` no longer satisfies this Protocol.

Reference: ``hermes_cli/plugins.py`` (PluginContext class, line 233; method
signature at line 301 as of Hermes 0.11.0).
"""

from collections.abc import Callable
from typing import Any, Protocol


class PluginContext(Protocol):
    """Subset of ``hermes_cli.plugins.PluginContext`` used by llm_guard."""

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None: ...
