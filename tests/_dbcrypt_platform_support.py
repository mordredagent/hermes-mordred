"""Policy-only OS simulation; checked filesystem code keeps the real host ABI."""

from __future__ import annotations

import sys
from types import SimpleNamespace


def policy_sys(platform: str) -> SimpleNamespace:
    """Give one policy module a sys view without mutating shared sys.platform.

    Keep real streams/modules for startup assertions and capture; callers still
    change the real argv when exercising the separate maintenance CLI parser.
    """
    return SimpleNamespace(**{**vars(sys), "platform": platform})
