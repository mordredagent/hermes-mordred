"""Best-effort audit entries for the import collectors: counts and codes only, never message content.

Kept outside :mod:`mordred_hermes.imports.mail`, which never imports :mod:`logging`; the
logger here only receives the audit writer's own failures.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Mapping
from typing import Any, Final

__all__ = ["append"]

_LOG: Final = logging.getLogger(__name__)


def append(entry: Mapping[str, Any]) -> None:
    """Append ``entry`` to ``<home>/mordred/audit.log`` through the shared encryption-aware writer."""
    with contextlib.suppress(Exception):
        from .._audit_support import build_audit_writer, safe_audit_append
        from .._home import hermes_home

        writer = build_audit_writer(hermes_home() / "mordred" / "audit.log")
        safe_audit_append(writer, entry, logger=_LOG)
