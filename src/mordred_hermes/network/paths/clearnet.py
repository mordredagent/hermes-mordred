"""Clearnet path — the no-op baseline.

No subprocess, no liveness probe, no env mutation here (that's
``proxy_env``'s job). Exists for symmetry with ``tor`` / ``vpn`` so
:mod:`mordred_hermes.network.runtime` (Phase 3 PR2) can dispatch on a
single ``Path`` interface.

The handle is an immutable sentinel; callers must treat it as opaque
because ``tor`` / ``vpn`` handles carry process state. Phase 3 PR2 wires
all three handles through a :class:`~typing.Protocol` in ``api.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

PATH_NAME: Final[str] = "clearnet"


@dataclass(frozen=True, slots=True)
class ClearnetHandle:
    """Inert handle returned by :func:`start`. No state to track."""


def start() -> ClearnetHandle:
    """Return an inert handle. Always succeeds; no work performed."""
    return ClearnetHandle()


def stop(handle: ClearnetHandle) -> None:
    """No-op tear-down. Accepts a handle for API symmetry only."""
    del handle


def health(handle: ClearnetHandle) -> bool:
    """Always healthy — nothing to probe."""
    del handle
    return True
