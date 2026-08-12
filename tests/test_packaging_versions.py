"""Tests guarding the PyPI release version invariants.

Four invariants are pinned here:

1. **Name-reservation ordering (M7, TODO §0.5 L70).** M7 reserves the
   ``mordred-hermes`` distribution name on TestPyPI/PyPI by uploading an
   intentionally empty stub *before* the real implementation ships. The stub
   lives at ``packaging/name-reservation/pyproject.toml``. After the rename,
   that project is continued by the metadata-only compatibility shim.

2. **Rename reservation (2026-08-12).** The canonical
   ``hermes-mordred`` distribution has its own empty ``0.0.0.dev0`` stub. It
   shares its project name with the real root package after cutover.

3. **Compatibility ownership.** The ``mordred-hermes`` shim matches the real
   version, depends on that exact ``hermes-mordred`` release, forwards every
   extra, and is configured to build a metadata-only wheel.

4. **Single-source version consistency (TODO §0.5 L64).** The real package no
   longer hardcodes its version in pyproject. It is sourced dynamically from
   ``src/mordred_hermes/__about__.py`` (Hatch ``[tool.hatch.version] path``),
   which lives inside the importable package so sdist->wheel builds resolve it
   without the docs tree. The docs marker (``docs/dev/VERSION``), every
   ``plugin.yaml``, and the copy-paste install commands in ``README.md``
   (the status line + every ``hermes-mordred[...]==`` install pin) and
   ``docs/dev/setup.md`` (the ``--reinstall`` pin) must all match that single
   source — otherwise a release bump that touches only some of them ships an
   inconsistent version. ``tools/bump_version.py`` rewrites all of them in
   lockstep; these tests are the net that catches a hand-edit that forgets
   one.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import pytest
from packaging.version import Version

#: Repository root — holds the real package pyproject and the docs tree.
_PKG_ROOT = Path(__file__).resolve().parent.parent

#: The empty stub uploaded first to claim the name (M7).
_STUB_PYPROJECT = _PKG_ROOT / "packaging" / "name-reservation" / "pyproject.toml"

#: The historical stub that reserved the target distribution name before the
#: root package adopted it. It now deliberately shares the canonical name while
#: remaining permanently below every real release.
_RENAME_STUB_PYPROJECT = _PKG_ROOT / "packaging" / "hermes-mordred-reservation" / "pyproject.toml"

#: Metadata-only continuation of the old distribution name.
_COMPAT_PYPROJECT = _PKG_ROOT / "packaging" / "mordred-hermes-compat" / "pyproject.toml"

#: Release mode routing consumed directly by release.yml.
_RELEASE_PROJECTS = _PKG_ROOT / "packaging" / "release-projects.toml"

#: The real Mordred plugin bundle.
_REAL_PYPROJECT = _PKG_ROOT / "pyproject.toml"

#: The importable package's single source of version truth (Hatch reads this).
_ABOUT = _PKG_ROOT / "src" / "mordred_hermes" / "__about__.py"

#: Human-facing version marker in the docs tree (a mirror of ``_ABOUT``).
_DOC_VERSION = _PKG_ROOT / "docs" / "dev" / "VERSION"

#: The top-level README — ships copy-paste install commands pinned to a
#: version. Part of the sdist/repo, so unlike the docs tree it is always
#: present.
_README = _PKG_ROOT / "README.md"

#: Dev-setup doc with a version-pinned ``--reinstall`` example. Absent from
#: the installed-package context (docs tree not shipped), same as
#: ``_DOC_VERSION``.
_SETUP_MD = _PKG_ROOT / "docs" / "dev" / "setup.md"

#: Matches ``hermes-mordred[extra1,extra2]==<version>`` install pins and
#: captures the version. Requiring the version to start with a digit
#: deliberately excludes the ``==<new-version>`` placeholder in README's
#: Upgrading section — that's prose, not a real pin to check.
_INSTALL_PIN_RE = re.compile(r"hermes-mordred\[[^\]]*\]==([0-9][^\s\"'#]*)")


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


def test_distribution_names_follow_the_cutover_contract() -> None:
    """Reservation sources stay attached to the project they originally claimed."""
    assert _read(_STUB_PYPROJECT)["name"] == _read(_COMPAT_PYPROJECT)["name"] == "mordred-hermes"
    assert _read(_RENAME_STUB_PYPROJECT)["name"] == _read(_REAL_PYPROJECT)["name"] == "hermes-mordred"


def test_real_pyproject_sources_version_dynamically() -> None:
    """The real package must source its version from ``__about__.py``, not inline.

    Guards against someone re-introducing a hardcoded ``version`` (which would
    silently diverge from the single source and defeat ``bump_version.py``).
    """
    project = _read(_REAL_PYPROJECT)
    assert "version" not in project, "real version must be dynamic, not hardcoded in [project]"
    assert "version" in project.get("dynamic", []), "real pyproject must declare dynamic version"


def test_legacy_stub_version_is_strictly_below_compat_version() -> None:
    """The stub must sort below the compatibility release per PEP 440 ordering.

    Otherwise the real ``release.yml`` publish would be rejected by PyPI as an
    older-or-equal version of an already-claimed name.
    """
    stub = Version(str(_read(_STUB_PYPROJECT)["version"]))
    compat = Version(str(_read(_COMPAT_PYPROJECT)["version"]))
    assert stub < compat, f"stub {stub} must be < compatibility release {compat}"


def test_stub_version_is_a_dev_release() -> None:
    """The reservation stub is a ``.devN`` release — never a real version."""
    assert Version(str(_read(_STUB_PYPROJECT)["version"])).is_devrelease


def test_rename_stub_version_is_a_dev_release_below_the_real_version() -> None:
    """The reservation must never sort as a real release."""
    stub = Version(str(_read(_RENAME_STUB_PYPROJECT)["version"]))
    assert stub.is_devrelease
    assert stub < Version(_real_version())


def test_compatibility_shim_matches_and_forwards_the_real_release() -> None:
    real = _read(_REAL_PYPROJECT)
    compat = _read(_COMPAT_PYPROJECT)
    version = _real_version()

    assert compat["version"] == version
    assert compat["dependencies"] == [f"hermes-mordred=={version}"]
    real_extras = real["optional-dependencies"]
    compat_extras = compat["optional-dependencies"]
    assert isinstance(real_extras, dict)
    assert isinstance(compat_extras, dict)
    assert set(compat_extras) == set(real_extras)
    assert compat_extras == {extra: [f"hermes-mordred[{extra}]=={version}"] for extra in real_extras}


def test_compatibility_shim_declares_no_runtime_files_or_entry_points() -> None:
    with _COMPAT_PYPROJECT.open("rb") as stream:
        metadata = tomllib.load(stream)

    project = metadata["project"]
    assert "scripts" not in project
    assert "entry-points" not in project
    assert metadata["tool"]["hatch"]["build"]["targets"]["wheel"] == {"bypass-selection": True}


def test_release_project_contract_matches_package_metadata() -> None:
    """Every publish mode must resolve to the intended on-disk project."""
    with _RELEASE_PROJECTS.open("rb") as stream:
        modes = tomllib.load(stream)["mode"]

    assert modes == {
        "reserve": {
            "directory": "packaging/name-reservation",
            "name": "mordred-hermes",
            "reservation": True,
        },
        "reserve-rename": {
            "directory": "packaging/hermes-mordred-reservation",
            "name": "hermes-mordred",
            "reservation": True,
        },
        "release": {
            "directory": ".",
            "name": "hermes-mordred",
            "reservation": False,
        },
        "compat": {
            "directory": "packaging/mordred-hermes-compat",
            "name": "mordred-hermes",
            "reservation": False,
        },
    }
    for project in modes.values():
        pyproject = _PKG_ROOT / project["directory"] / "pyproject.toml"
        assert _read(pyproject)["name"] == project["name"]


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


def test_install_doc_pins_match_package_version() -> None:
    """Copy-paste install commands in the docs must pin the real version.

    ``_INSTALL_PIN_RE`` requires the captured version to start with a digit,
    which deliberately skips the ``==<new-version>`` placeholders in
    README's Upgrading section — those are prose showing the shape of the
    command, not a pin that should track the current release.
    """
    assert _README.exists(), "README.md ships in the sdist and must be present"
    version = _real_version()

    readme_pins = _INSTALL_PIN_RE.findall(_README.read_text(encoding="utf-8"))
    # A minimum-count guard: if the docs are ever rewritten to drop the pins
    # entirely, ``findall`` would silently return `[]` and the mismatch
    # assertion below would vacuously pass. Requiring at least 3 (macOS,
    # keyvault, and the extension-serve pin) keeps this test honest.
    assert len(readme_pins) >= 3, f"expected >=3 install pins in README.md, found {len(readme_pins)}"
    mismatched_readme = [p for p in readme_pins if p != version]
    assert not mismatched_readme, (
        f"README.md install pins out of sync with package version {version!r}: {mismatched_readme}; "
        "run tools/bump_version.py to sync"
    )

    if not _SETUP_MD.exists():
        pytest.skip("docs tree absent (installed-package context, not a source checkout)")
    setup_pins = _INSTALL_PIN_RE.findall(_SETUP_MD.read_text(encoding="utf-8"))
    assert len(setup_pins) >= 1, f"expected >=1 install pin in docs/dev/setup.md, found {len(setup_pins)}"
    mismatched_setup = [p for p in setup_pins if p != version]
    assert not mismatched_setup, (
        f"docs/dev/setup.md install pin out of sync with package version {version!r}: {mismatched_setup}; "
        "run tools/bump_version.py to sync"
    )


def test_readme_status_line_matches_package_version() -> None:
    """The README status line's ``current release`` marker must match the package."""
    match = re.search(r"current release `([^`]+)`", _README.read_text(encoding="utf-8"))
    assert match is not None, "README.md missing the `current release `...`` status marker"
    assert match.group(1) == _real_version(), (
        f"README status line {match.group(1)!r} != package {_real_version()!r}; run tools/bump_version.py to sync"
    )
