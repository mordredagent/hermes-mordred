"""Real PowerShell installer acceptance; no TPM is needed for build tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("MORDRED_WINKEY_BUILD_TEST") != "1",
    reason="requires explicit Windows build-tool test environment",
)


@pytest.fixture(scope="module")
def source() -> Path:
    return Path(os.environ.get("MORDRED_WINKEY_SOURCE", Path(__file__).resolve().parents[1] / "native/winkey-helper"))


def install(source: Path, destination: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(source / "build.ps1"),
            "-InstallDir",
            str(destination),
            "-Python",
            sys.executable,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def installed(source: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("winkey-install") / "Hermes 日本語 bin"
    result = install(source, destination)
    assert result.returncode == 0, result.stdout + result.stderr
    binary = destination / "mordred-hermes-winkey.exe"
    assert binary.read_bytes()[:2] == b"MZ"
    result = subprocess.run([str(binary)], input=b'{"cmd":"unknown"}', capture_output=True, timeout=15)
    assert result.returncode != 0 and b'"error"' in result.stdout
    return binary


def test_windows_build_install_unicode_and_replace(source: Path, installed: Path) -> None:
    before = digest(installed)
    result = install(source, installed.parent)
    assert result.returncode == 0, result.stdout + result.stderr
    assert digest(installed) == before
    assert list(installed.parent.iterdir()) == [installed]


def test_windows_failed_build_retains_existing(source: Path, installed: Path, tmp_path: Path) -> None:
    broken = tmp_path / "broken source"
    shutil.copytree(source, broken, ignore=shutil.ignore_patterns("target"))
    (broken / "Cargo.toml").write_text("not valid TOML", encoding="utf-8")
    before = digest(installed)
    result = install(broken, installed.parent)
    assert result.returncode != 0
    assert digest(installed) == before
    assert list(installed.parent.iterdir()) == [installed]


def test_windows_running_destination_retains_existing(source: Path, installed: Path) -> None:
    before = digest(installed)
    # The actual helper waits for bounded stdin while Windows maps its image.
    child = subprocess.Popen([str(installed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert child.poll() is None
        result = install(source, installed.parent)
        assert result.returncode != 0, result.stdout + result.stderr
        assert digest(installed) == before
        assert list(installed.parent.iterdir()) == [installed]
    finally:
        child.communicate(b'{"cmd":"unknown"}', timeout=15)
