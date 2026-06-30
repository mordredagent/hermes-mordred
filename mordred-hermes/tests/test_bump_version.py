"""Tests for the release version bump helper (``tools/bump_version.py``).

The tool rewrites the version across every surface (the canonical
``__about__.py``, the docs ``VERSION`` marker, and every ``plugin.yaml``). A
bad bump that desyncs them would only be caught later by
``test_packaging_versions.py``; these tests exercise the tool directly against
a throwaway tree (``tmp_path`` + monkeypatched module paths) so its own logic —
lockstep rewrite, dry-run, the monotonic/validity guards, and PEP 440
canonicalization — is verified without touching the real repository.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "tools" / "bump_version.py"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bump_version_under_test", _TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def bump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Path, Path, list[Path]]:
    """Load the tool and point its module-level paths at a throwaway tree."""
    mod = _load_tool()

    pkg = tmp_path / "mordred-hermes"
    about = pkg / "src" / "mordred_hermes" / "__about__.py"
    about.parent.mkdir(parents=True)
    about.write_text('__version__ = "0.1.0a0"\n', encoding="utf-8")

    doc = tmp_path / "mordred-docs" / "dev" / "VERSION"
    doc.parent.mkdir(parents=True)
    doc.write_text("0.1.0a0\n", encoding="utf-8")

    manifests: list[Path] = []
    for name in ("keyvault", "wizard"):
        manifest = pkg / "src" / "mordred_hermes" / name / "plugin.yaml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(f"name: mordred_{name}\nversion: 0.1.0a0\ndescription: x\n", encoding="utf-8")
        manifests.append(manifest)

    monkeypatch.setattr(mod, "_PKG_ROOT", pkg)
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(mod, "_ABOUT", about)
    monkeypatch.setattr(mod, "_DOC_VERSION", doc)
    return mod, about, doc, manifests


def test_bump_updates_every_surface_in_lockstep(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, about, doc, manifests = bump
    assert mod.main(["0.1.0b0"]) == 0
    assert '__version__ = "0.1.0b0"' in about.read_text(encoding="utf-8")
    assert doc.read_text(encoding="utf-8").strip() == "0.1.0b0"
    for manifest in manifests:
        assert "version: 0.1.0b0" in manifest.read_text(encoding="utf-8")


def test_dry_run_writes_nothing(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, about, doc, manifests = bump
    assert mod.main(["0.1.0b0", "--dry-run"]) == 0
    assert '__version__ = "0.1.0a0"' in about.read_text(encoding="utf-8")
    assert doc.read_text(encoding="utf-8").strip() == "0.1.0a0"
    for manifest in manifests:
        assert "version: 0.1.0a0" in manifest.read_text(encoding="utf-8")


def test_non_increasing_version_is_rejected(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, about, *_ = bump
    with pytest.raises(SystemExit):
        mod.main(["0.1.0a0"])  # equal to current
    # File left untouched.
    assert '__version__ = "0.1.0a0"' in about.read_text(encoding="utf-8")


def test_invalid_version_is_rejected(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, *_ = bump
    with pytest.raises(SystemExit):
        mod.main(["not-a-pep440-version"])


def test_version_is_canonicalized(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, about, doc, _ = bump
    assert mod.main(["0.1.0-alpha2"]) == 0  # PEP 440 canonical form is 0.1.0a2
    assert '__version__ = "0.1.0a2"' in about.read_text(encoding="utf-8")
    assert doc.read_text(encoding="utf-8").strip() == "0.1.0a2"


def test_allow_non_increasing_resyncs_drifted_files(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, _about, _doc, manifests = bump
    # Simulate a hand-edit that left one manifest behind.
    manifests[0].write_text("name: drifted\nversion: 0.0.1\ndescription: y\n", encoding="utf-8")
    assert mod.main(["0.1.0a0", "--allow-non-increasing"]) == 0
    assert "version: 0.1.0a0" in manifests[0].read_text(encoding="utf-8")
