"""Ensure both the repo root (for ``gateway``) and the ``mordred_hermes`` package
source are importable. In CI the package is installed editable; locally we add
``mordred-hermes/src`` to the path so the suite runs without an install."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "mordred-hermes" / "src"

for _p in (_REPO_ROOT, _SRC):
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
