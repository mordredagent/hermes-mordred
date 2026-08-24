"""Tests for the release version bump helper (``tools/bump_version.py``).

The tool rewrites the version across every surface (the canonical
``__about__.py``, the docs ``VERSION`` marker, every ``plugin.yaml``, the
README.md / docs/dev/setup.md install pins, and the exact compatibility-shim
requirements). A bad bump that desyncs them would only be caught later by
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

    pkg = tmp_path / "hermes-mordred"
    about = pkg / "src" / "mordred_hermes" / "__about__.py"
    about.parent.mkdir(parents=True)
    about.write_text('__version__ = "0.1.0a0"\n', encoding="utf-8")

    doc = pkg / "docs" / "dev" / "VERSION"
    doc.parent.mkdir(parents=True)
    doc.write_text("0.1.0a0\n", encoding="utf-8")

    # README.md / docs/dev/setup.md carry copy-paste install pins too (see
    # `_INSTALL_PIN_RE` / `_README_STATUS_RE` in the tool). Without pointing
    # these at throwaway copies, `mod.main()` would rewrite this repo's real
    # README.md / docs/dev/setup.md on every non-dry-run test below, since
    # the tool's `_README` / `_SETUP_MD` module constants are bound to the
    # real repo root at import time, before `_PKG_ROOT` is monkeypatched.
    readme = pkg / "README.md"
    readme.write_text(
        "**Status: active alpha** — current release `0.1.0a0`\n\n"
        'uv pip install --python p "hermes-mordred[macos]==0.1.0a0"\n'
        'uv pip install --python p "hermes-mordred[keyvault]==0.1.0a0"\n',
        encoding="utf-8",
    )

    setup_md = pkg / "docs" / "dev" / "setup.md"
    setup_md.write_text(
        'uv pip install --python p --reinstall "hermes-mordred[macos]==0.1.0a0"\n',
        encoding="utf-8",
    )

    compat_pyproject = pkg / "packaging" / "mordred-hermes-compat" / "pyproject.toml"
    compat_pyproject.parent.mkdir(parents=True)
    compat_pyproject.write_text(
        '[project]\nversion = "0.1.0a0"\n'
        'dependencies = ["hermes-mordred==0.1.0a0"]\n'
        "[project.optional-dependencies]\n"
        'macos = ["hermes-mordred[macos]==0.1.0a0"]\n',
        encoding="utf-8",
    )

    manifests: list[Path] = []
    for name in ("keyvault", "wizard"):
        manifest = pkg / "src" / "mordred_hermes" / name / "plugin.yaml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(f"name: mordred_{name}\nversion: 0.1.0a0\ndescription: x\n", encoding="utf-8")
        manifests.append(manifest)

    monkeypatch.setattr(mod, "_PKG_ROOT", pkg)
    monkeypatch.setattr(mod, "_ABOUT", about)
    monkeypatch.setattr(mod, "_DOC_VERSION", doc)
    monkeypatch.setattr(mod, "_README", readme)
    monkeypatch.setattr(mod, "_SETUP_MD", setup_md)
    monkeypatch.setattr(mod, "_COMPAT_PYPROJECT", compat_pyproject)
    return mod, about, doc, manifests


def test_bump_updates_every_surface_in_lockstep(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, about, doc, manifests = bump
    assert mod.main(["0.1.0b0"]) == 0
    assert '__version__ = "0.1.0b0"' in about.read_text(encoding="utf-8")
    assert doc.read_text(encoding="utf-8").strip() == "0.1.0b0"
    for manifest in manifests:
        assert "version: 0.1.0b0" in manifest.read_text(encoding="utf-8")
    readme_text = mod._README.read_text(encoding="utf-8")
    assert "current release `0.1.0b0`" in readme_text
    assert 'hermes-mordred[macos]==0.1.0b0"' in readme_text
    assert 'hermes-mordred[keyvault]==0.1.0b0"' in readme_text
    assert 'hermes-mordred[macos]==0.1.0b0"' in mod._SETUP_MD.read_text(encoding="utf-8")
    compat_text = mod._COMPAT_PYPROJECT.read_text(encoding="utf-8")
    assert 'version = "0.1.0b0"' in compat_text
    assert 'hermes-mordred==0.1.0b0"' in compat_text
    assert 'hermes-mordred[macos]==0.1.0b0"' in compat_text


def test_next_steps_follow_pr_changelog_and_editable_metadata_conventions(
    bump: tuple[ModuleType, Path, Path, list[Path]], capsys: pytest.CaptureFixture[str]
) -> None:
    mod, *_ = bump

    assert mod.main(["0.1.0b0"]) == 0

    out = capsys.readouterr().out
    assert "Changes/Fixes entry" in out
    assert "changelog entry" not in out.lower()
    assert "uv sync --all-extras --reinstall-package hermes-mordred" in out


def test_dry_run_writes_nothing(bump: tuple[ModuleType, Path, Path, list[Path]]) -> None:
    mod, about, doc, manifests = bump
    assert mod.main(["0.1.0b0", "--dry-run"]) == 0
    assert '__version__ = "0.1.0a0"' in about.read_text(encoding="utf-8")
    assert doc.read_text(encoding="utf-8").strip() == "0.1.0a0"
    for manifest in manifests:
        assert "version: 0.1.0a0" in manifest.read_text(encoding="utf-8")
    readme_text = mod._README.read_text(encoding="utf-8")
    assert "current release `0.1.0a0`" in readme_text
    assert 'hermes-mordred[macos]==0.1.0a0"' in readme_text
    assert 'hermes-mordred[macos]==0.1.0a0"' in mod._SETUP_MD.read_text(encoding="utf-8")
    assert 'version = "0.1.0a0"' in mod._COMPAT_PYPROJECT.read_text(encoding="utf-8")


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
