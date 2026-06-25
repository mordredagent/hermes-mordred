"""Tests guarding the PyPI release version invariants.

Two invariants are pinned here:

1. **Name-reservation ordering (M7, TODO §0.5 L70).** M7 reserves the
   ``mordred-hermes`` distribution name on TestPyPI/PyPI by uploading an
   intentionally empty stub *before* the real implementation ships. The stub
   lives at ``packaging/name-reservation/pyproject.toml``; the real package is
   the top-level ``mordred-hermes/pyproject.toml``. PyPI never allows
   re-uploading a deleted version, so the stub version is permanent. If the
   stub version were >= the real version, the real release could never be
   published under the same name.

2. **Single-source version consistency (TODO §0.5 L64).** The real package no
   longer hardcodes its version in pyproject. It is sourced dynamically from
   ``src/mordred_hermes/__about__.py`` (Hatch ``[tool.hatch.version] path``),
   which lives inside the importable package so sdist->wheel builds resolve it
   without the docs tree. The docs marker (``mordred-docs/dev/VERSION``)
   and every ``plugin.yaml`` must match that single source — otherwise a
   release bump that touches only some of them ships an inconsistent version.
   ``tools/bump_version.py`` rewrites all of them in lockstep; these tests are
   the net that catches a hand-edit that forgets one.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import pytest
from packaging.version import Version

#: ``mordred-hermes/`` — the directory holding the real package pyproject.
_PKG_ROOT = Path(__file__).resolve().parent.parent

#: Repository root — ``mordred-hermes/``'s parent, which holds the docs tree.
_REPO_ROOT = _PKG_ROOT.parent

#: The empty stub uploaded first to claim the name (M7).
_STUB_PYPROJECT = _PKG_ROOT / "packaging" / "name-reservation" / "pyproject.toml"

#: The real Mordred plugin bundle.
_REAL_PYPROJECT = _PKG_ROOT / "pyproject.toml"

#: The importable package's single source of version truth (Hatch reads this).
_ABOUT = _PKG_ROOT / "src" / "mordred_hermes" / "__about__.py"

#: Human-facing version marker in the docs tree (a mirror of ``_ABOUT``).
_DOC_VERSION = _REPO_ROOT / "mordred-docs" / "dev" / "VERSION"


def _read(pyproject: Path) -> dict[str, object]:
    """Return the ``[project]`` table of ``pyproject``."""
    with pyproject.open("rb") as fh:
        return dict(tomllib.load(fh)["project"])


def _real_version() -> str:
    """Resolve the real package version from its dynamic source.

    The real pyproject declares ``dynamic = ["version"]`` and sources the value
    from ``__about__.py`` via Hatch's ``path`` version source, so there is no
    static ``[project].version`` to read. Parse the assignment with ``ast`` so
    we read exactly what Hatch reads — no import side effects.
    """
    tree = ast.parse(_ABOUT.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return value
    raise AssertionError(f"__version__ assignment not found in {_ABOUT}")


def _plugin_manifests() -> list[Path]:
    """Every plugin manifest shipped in the package."""
    return sorted(_PKG_ROOT.glob("src/mordred_hermes/*/plugin.yaml"))


def _manifest_version(manifest: Path) -> str:
    """Read the ``version:`` field from a plugin.yaml without a YAML dep.

    Captures the first bare token after ``version:``, tolerating optional
    quoting and a trailing inline comment so the consistency check keeps
    working if a manifest later gains either.
    """
    match = re.search(r"""(?m)^version:\s*['"]?([^\s'"#]+)""", manifest.read_text(encoding="utf-8"))
    assert match is not None, f"no `version:` field in {manifest}"
    return match.group(1)


def test_stub_and_real_share_the_distribution_name() -> None:
    """Both pyprojects must declare the same ``name`` — they are one project."""
    assert _read(_STUB_PYPROJECT)["name"] == _read(_REAL_PYPROJECT)["name"] == "mordred-hermes"


def test_real_pyproject_sources_version_dynamically() -> None:
    """The real package must source its version from ``__about__.py``, not inline.

    Guards against someone re-introducing a hardcoded ``version`` (which would
    silently diverge from the single source and defeat ``bump_version.py``).
    """
    project = _read(_REAL_PYPROJECT)
    assert "version" not in project, "real version must be dynamic, not hardcoded in [project]"
    assert "version" in project.get("dynamic", []), "real pyproject must declare dynamic version"


def test_stub_version_is_strictly_below_real_version() -> None:
    """The stub must sort below the real release per PEP 440 ordering.

    Otherwise the real ``release.yml`` publish would be rejected by PyPI as an
    older-or-equal version of an already-claimed name.
    """
    stub = Version(str(_read(_STUB_PYPROJECT)["version"]))
    real = Version(_real_version())
    assert stub < real, f"stub {stub} must be < real {real} so the real release can publish"


def test_stub_version_is_a_dev_release() -> None:
    """The reservation stub is a ``.devN`` release — never a real version."""
    assert Version(str(_read(_STUB_PYPROJECT)["version"])).is_devrelease


def test_doc_version_marker_matches_package_version() -> None:
    """The docs-tree VERSION marker must mirror the package's single source."""
    if not _DOC_VERSION.exists():
        pytest.skip("docs tree absent (installed-package context, not a source checkout)")
    marker = _DOC_VERSION.read_text(encoding="utf-8").strip()
    assert marker == _real_version(), (
        f"docs VERSION {marker!r} != package {_real_version()!r}; run tools/bump_version.py to sync"
    )


def test_plugin_manifest_versions_match_package_version() -> None:
    """Every plugin.yaml version must match the package's single source."""
    manifests = _plugin_manifests()
    assert manifests, "expected plugin.yaml manifests under src/mordred_hermes/*/"
    version = _real_version()
    mismatched = {m.parent.name: v for m in manifests if (v := _manifest_version(m)) != version}
    assert not mismatched, (
        f"plugin manifests out of sync with package version {version!r}: {mismatched}; "
        "run tools/bump_version.py to sync"
    )
