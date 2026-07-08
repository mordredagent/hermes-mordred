"""Unit tests for the canonical policy/path type module.

The point of ``_policy_types`` is that the type-level (``Literal``) and
runtime-level (tuple / frozenset) views of the two closed string sets can
never disagree — these tests pin the derivation and the display ordering
that ``wizard._network_answers`` relies on, plus the stdlib-only import
contract the module docstring promises.
"""

from __future__ import annotations

import subprocess
import sys
from typing import get_args

from mordred_hermes._policy_types import (
    ACTIVE_PATHS,
    POLICY_MODES,
    VALID_ACTIVE_PATHS,
    VALID_POLICY_MODES,
    ActivePath,
    PolicyMode,
)


def test_runtime_views_derive_from_literals() -> None:
    assert get_args(PolicyMode) == POLICY_MODES
    assert get_args(ActivePath) == ACTIVE_PATHS
    assert frozenset(POLICY_MODES) == VALID_POLICY_MODES
    assert frozenset(ACTIVE_PATHS) == VALID_ACTIVE_PATHS


def test_declaration_order_is_preserved_for_display() -> None:
    assert POLICY_MODES == ("strict", "lenient", "off")
    assert ACTIVE_PATHS == ("tor", "vpn", "clearnet")


def test_import_pulls_no_optional_dependencies() -> None:
    # The module promises to be importable at plugin-registration time
    # without optional deps; a fresh interpreter proves it (importing it
    # in-process would be polluted by whatever this test run loaded first).
    code = (
        "import sys; import mordred_hermes._policy_types; "
        "bad = [m for m in sys.modules if m.startswith(('ruamel', 'cryptography', 'argon2', 'blake3'))]; "
        "sys.exit(1 if bad else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], check=False)
    assert result.returncode == 0
