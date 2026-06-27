"""Backward-compat facade — ``_term`` relocated to :mod:`mordred_hermes._term`.

The terminal-styling helper now lives at the package root so non-wizard
packages (e.g. ``keyvault._env_write_guard``) can reuse it without importing
the wizard layer. This module re-exports the full public API at the historical
``mordred_hermes.wizard._term`` path so the wizard call sites that do
``from . import _term`` — and the tests / monkeypatch pins that import
``from mordred_hermes.wizard import _term`` — keep working unchanged.

New code should import from :mod:`mordred_hermes._term` directly.
"""

from __future__ import annotations

from .._term import *  # noqa: F403  — re-export the public styling API
from .._term import __all__ as __all__
