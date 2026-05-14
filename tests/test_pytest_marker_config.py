"""Contract: the ``integration`` pytest marker is registered AND the
default ``addopts`` filters integration tests out of the unit run.

Codex review (2026-05-14, P2-1): without this, ``pytest`` invoked from
``mordred-hermes/`` on a Linux machine with Docker running would also
start the Tor container during the unit-test matrix — duplicating CI
work and coupling unit-test stability to Docker bootstrap. The
dedicated ``integration-tor`` CI job opts back in via ``-m integration``.

This file is a unit test (not itself marked ``integration``) so it is
collected and run in the default suite. It asserts the project's
pytest configuration matches the contract we rely on.
"""

from __future__ import annotations

import shlex
import tomllib
from pathlib import Path

_PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


def _pytest_options() -> dict[str, object]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return data["tool"]["pytest"]["ini_options"]


def test_integration_marker_registered() -> None:
    """``markers`` table must declare ``integration`` so ``--strict-markers``
    accepts ``@pytest.mark.integration`` without raising."""
    opts = _pytest_options()
    markers = opts.get("markers", [])
    assert isinstance(markers, list), f"markers should be a list, got {type(markers)}"
    declared = [m.split(":", 1)[0].strip() for m in markers]
    assert "integration" in declared, (
        f"`integration` marker must be declared in [tool.pytest.ini_options] markers; got {declared}"
    )


def test_default_addopts_filters_out_integration() -> None:
    """``addopts`` must include ``-m "not integration"`` (or equivalent)
    so the default unit-test run skips integration suites. The dedicated
    CI jobs opt back in with ``-m integration``.
    """
    opts = _pytest_options()
    addopts = opts.get("addopts", "")
    assert isinstance(addopts, str), f"addopts should be a string, got {type(addopts)}"
    tokens = shlex.split(addopts)
    found = False
    for i, tok in enumerate(tokens):
        if tok == "-m" and i + 1 < len(tokens) and "not integration" in tokens[i + 1]:
            found = True
            break
    assert found, (
        "addopts must contain `-m 'not integration'` (or equivalent) so the default "
        f"unit run skips integration tests; got addopts={addopts!r}"
    )
