"""Make the ``mordred_hermes`` package importable when the suite runs without an
editable install. In CI the package is installed (``pip install -e .``); locally
this adds the plugin's ``src`` root to the path so ``mordred_hermes.extension.*``
resolves either way."""

from __future__ import annotations

import sys
from pathlib import Path

# tests/extension/conftest.py -> repo root is two levels up; the package lives
# under ``src`` in this plugin-only layout.
_SRC = Path(__file__).resolve().parents[2] / "src"
if _SRC.exists() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
