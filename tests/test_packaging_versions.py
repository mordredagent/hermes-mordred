"""Tests guarding the M7 PyPI name-reservation invariant.

M7 (TODO §0.5 L70) reserves the ``mordred-hermes`` distribution name on
TestPyPI/PyPI by uploading an intentionally empty stub *before* the real
implementation ships. The stub lives at
``packaging/name-reservation/pyproject.toml``; the real package is the
top-level ``mordred-hermes/pyproject.toml``.

PyPI never allows re-uploading a deleted version, so the stub version is
permanent. If the stub version were >= the real version, the real release
could never be published under the same name. This test pins the ordering
so a future version bump cannot silently break the release path.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.version import Version

#: ``mordred-hermes/`` — the directory holding the real package pyproject.
_PKG_ROOT = Path(__file__).resolve().parent.parent

#: The empty stub uploaded first to claim the name (M7).
_STUB_PYPROJECT = _PKG_ROOT / "packaging" / "name-reservation" / "pyproject.toml"

#: The real Mordred plugin bundle.
_REAL_PYPROJECT = _PKG_ROOT / "pyproject.toml"


def _read(pyproject: Path) -> dict[str, str]:
    """Return the ``[project]`` table of ``pyproject``."""
    with pyproject.open("rb") as fh:
        return dict(tomllib.load(fh)["project"])


def test_stub_and_real_share_the_distribution_name() -> None:
    """Both pyprojects must declare the same ``name`` — they are one project."""
    assert _read(_STUB_PYPROJECT)["name"] == _read(_REAL_PYPROJECT)["name"] == "mordred-hermes"


def test_stub_version_is_strictly_below_real_version() -> None:
    """The stub must sort below the real release per PEP 440 ordering.

    Otherwise the real ``release.yml`` publish would be rejected by PyPI as
    an older-or-equal version of an already-claimed name.
    """
    stub = Version(_read(_STUB_PYPROJECT)["version"])
    real = Version(_read(_REAL_PYPROJECT)["version"])
    assert stub < real, f"stub {stub} must be < real {real} so the real release can publish"


def test_stub_version_is_a_dev_release() -> None:
    """The reservation stub is a ``.devN`` release — never a real version."""
    assert Version(_read(_STUB_PYPROJECT)["version"]).is_devrelease
