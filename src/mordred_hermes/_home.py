"""Profile-aware Hermes home resolution shared across Mordred plugins.

Promoted from ``privacy_check/_runtime.py`` in Phase 1.3 because wizard,
network, and keyvault all need the same path. Kept narrow on purpose:
just the resolver and the frozen-at-import base path. Plugins should
build their own ``DEFAULT_*`` constants over :data:`HERMES_BASE` rather
than asking this module to enumerate them.

Resolution order:

1. ``hermes_constants.get_hermes_home()`` — honors ``HERMES_HOME`` env
   var and the ``active_profile`` file.
2. Fallback: the ``HERMES_HOME`` env var, else ``~/.hermes``. The fallback
   matters at interpreter startup under Hermes Desktop's managed launcher:
   its ``.pth`` files run while the Hermes checkout is off ``sys.path``, but
   the launcher has already exported ``HERMES_HOME``.

Resolved at import time. Mid-process ``HERMES_HOME`` flips do not
propagate; env vars must be set before plugin discovery (the documented
Hermes contract).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, cast


def hermes_home() -> Path:
    """Return Hermes's profile-aware home directory."""
    try:
        from hermes_constants import get_hermes_home
    except ImportError:
        env = os.environ.get("HERMES_HOME", "").strip()
        return Path(env).expanduser() if env else Path.home() / ".hermes"
    return cast(Path, get_hermes_home())


HERMES_BASE: Final = hermes_home()
