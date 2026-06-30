"""Default file paths owned or written by the wizard plugin.

Centralises the few constants that ``policy_writer.py``, ``upgrade.py``,
``policy_explainer.py``, ``audit_cli.py``, and ``install_dispatch.py``
all need so they share a single source of truth (and tests can override
via explicit kwargs).

PATHS.md row owners (Phase 1):

- ``~/.hermes/config.yaml``           — read+write (round-trip via ruamel)
- ``~/.hermes/mordred/policy.json``   — sole writer (privacy_check / llm_guard / network read)
- ``~/.hermes/mordred/audit.log``     — wizard READS (privacy_check writes)
- ``~/.hermes/mordred/.audit-migrated-from-openclaw`` — wizard sole writer (H5 idempotency marker)

OpenClaw legacy paths (Story 1.5 migration source, read-only for wizard).
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from .._home import HERMES_BASE

DEFAULT_HERMES_CONFIG_PATH: Final = HERMES_BASE / "config.yaml"
DEFAULT_MORDRED_DIR: Final = HERMES_BASE / "mordred"
DEFAULT_POLICY_JSON_PATH: Final = DEFAULT_MORDRED_DIR / "policy.json"
DEFAULT_AUDIT_LOG_PATH: Final = DEFAULT_MORDRED_DIR / "audit.log"
DEFAULT_OPENCLAW_MIGRATION_MARKER: Final = DEFAULT_MORDRED_DIR / ".audit-migrated-from-openclaw"

# OpenClaw legacy paths for Story 1.5 migration (PATHS.md §OpenClaw migration L286).
DEFAULT_OPENCLAW_BASE: Final = Path.home() / ".openclaw" / "mordred"
DEFAULT_OPENCLAW_AUDIT_PATH: Final = DEFAULT_OPENCLAW_BASE / "audit.log"
DEFAULT_OPENCLAW_POLICY_JSON_PATH: Final = DEFAULT_OPENCLAW_BASE / "policy.json"
DEFAULT_OPENCLAW_CREDENTIALS_DIR: Final = DEFAULT_OPENCLAW_BASE / "credentials"
DEFAULT_OPENCLAW_KEYVAULT_DIR: Final = DEFAULT_OPENCLAW_BASE / "keyvault"
DEFAULT_OPENCLAW_CONFIG_PATH: Final = Path.home() / ".openclaw" / "openclaw.json"
