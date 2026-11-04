"""``uv run python tools/provenance_eval <command>`` (or ``-m provenance_eval`` with ``tools`` on the path)."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__:
    from .cli import main
else:  # executed as a directory: import the package by name, not its modules as top-level names
    _HERE = Path(__file__).resolve().parent
    if sys.path and Path(sys.path[0] or ".").resolve() == _HERE:
        sys.path[0] = str(_HERE.parent)
    else:
        sys.path.insert(0, str(_HERE.parent))
    from provenance_eval.cli import main

raise SystemExit(main())
