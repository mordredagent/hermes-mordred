"""Guard that the built wheel bundles the ``sekey-helper`` Swift sources.

``hermes mordred keyvault enable-se`` builds the Secure Enclave helper from
``native/sekey-helper/`` at runtime. A source checkout has those sources, but
a ``pip install``-ed wheel only ships what the build config includes. This
test builds the wheel and asserts the helper sources land under the package
(``mordred_hermes/_native/sekey-helper/``) so ``_locate_helper_source`` can
find them post-install — while the Swift ``.build/`` artifacts stay out.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

#: ``mordred-hermes/`` — the directory holding the real package pyproject.
_PKG_ROOT = Path(__file__).resolve().parent.parent

#: Destination prefix the wheel must expose for the helper sources.
_WHEEL_PREFIX = "mordred_hermes/_native/sekey-helper/"


def _build_wheel(out_dir: Path, *, uv_cache_dir: Path) -> Path:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not available to build the wheel")
    proc = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(out_dir)],
        cwd=_PKG_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "UV_CACHE_DIR": str(uv_cache_dir)},
    )
    assert proc.returncode == 0, f"wheel build failed:\n{proc.stdout}\n{proc.stderr}"
    wheels = list(out_dir.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    return wheels[0]


@pytest.fixture(scope="module")
def wheel_names(tmp_path_factory: pytest.TempPathFactory) -> frozenset[str]:
    """Build once with a test-owned cache and share the immutable manifest."""
    root = tmp_path_factory.mktemp("native-wheel")
    wheel = _build_wheel(root / "dist", uv_cache_dir=root / "uv-cache")
    with zipfile.ZipFile(wheel) as archive:
        return frozenset(archive.namelist())


def test_wheel_bundles_sekey_helper_sources(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert _WHEEL_PREFIX + "build.sh" in names
    assert _WHEEL_PREFIX + "Package.swift" in names
    assert any(n.startswith(_WHEEL_PREFIX + "Sources/") and n.endswith("main.swift") for n in names)


def test_wheel_excludes_swift_build_artifacts(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert not any(".build/" in n for n in names), "Swift .build/ artifacts must not ship in the wheel"
    assert not any(n.endswith(".o") for n in names), "object files must not ship in the wheel"


#: Destination prefix the wheel must expose for the TPM helper sources (v2-OS2 2c).
_TPMKEY_WHEEL_PREFIX = "mordred_hermes/_native/tpmkey-helper/"


def test_wheel_bundles_tpmkey_helper_sources(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert _TPMKEY_WHEEL_PREFIX + "build.sh" in names
    assert _TPMKEY_WHEEL_PREFIX + "Cargo.toml" in names
    assert any(n.startswith(_TPMKEY_WHEEL_PREFIX + "src/") and n.endswith("main.rs") for n in names)


def test_wheel_excludes_rust_target_artifacts(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert not any("tpmkey-helper/target/" in n for n in names), "Rust target/ artifacts must not ship in the wheel"
