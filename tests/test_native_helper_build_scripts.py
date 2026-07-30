"""Regression tests for atomic native-helper installation."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_HELPERS = (
    ("sekey-helper", "MORDRED_SEKEY_INSTALL_DIR", "mordred-hermes-sekey"),
    ("tpmkey-helper", "MORDRED_TPMKEY_INSTALL_DIR", "mordred-hermes-tpmkey"),
)


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _prepare_fake_tools(fake_bin: Path) -> None:
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "swift",
        """#!/usr/bin/env bash
set -euo pipefail
out="$PWD/fake-release"
if [[ "$*" == *"--show-bin-path"* ]]; then
    mkdir -p "$out"
    printf '%s\\n' "$out"
    exit 0
fi
mkdir -p "$out"
printf 'complete-new-helper' > "$out/mordred-hermes-sekey"
chmod 0755 "$out/mordred-hermes-sekey"
""",
    )
    _write_executable(
        fake_bin / "cargo",
        """#!/usr/bin/env bash
set -euo pipefail
mkdir -p target/release
printf 'complete-new-helper' > target/release/mordred-hermes-tpmkey
chmod 0755 target/release/mordred-hermes-tpmkey
""",
    )
    _write_executable(fake_bin / "codesign", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(
        fake_bin / "sync",
        """#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "${SYNC_COUNT_FILE:?}" ]]; then
    count="$(<"${SYNC_COUNT_FILE}")"
fi
count=$((count + 1))
printf '%s\\n' "$count" > "${SYNC_COUNT_FILE}"
if [[ "${FAIL_SYNC_AT:-0}" == "$count" ]]; then
    exit 74
fi
exit 0
""",
    )
    _write_executable(
        fake_bin / "cp",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${FAIL_COPY:-0}" == 1 ]]; then
    printf 'partial-copy' > "$2"
    exit 73
fi
exec "${REAL_CP:?}" "$@"
""",
    )


def _run_installer(
    tmp_path: Path,
    helper_dir: str,
    install_env: str,
    binary_name: str,
    *,
    failure: str | None,
    existing_target: str = "file",
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    work = tmp_path / helper_dir
    work.mkdir()
    shutil.copy2(_REPO_ROOT / "native" / helper_dir / "build.sh", work / "build.sh")

    install_dir = tmp_path / "install"
    install_dir.mkdir()
    target = install_dir / binary_name
    if existing_target == "file":
        target.write_bytes(b"known-good-helper")
        target.chmod(0o755)
    elif existing_target == "directory":
        target.mkdir()
    elif existing_target == "symlink":
        symlink_target = tmp_path / "outside-helper"
        symlink_target.write_bytes(b"outside-helper")
        target.symlink_to(symlink_target)
    elif existing_target == "fifo":
        os.mkfifo(target, mode=0o600)
    else:  # pragma: no cover - test helper programming error
        raise AssertionError(f"unknown target kind: {existing_target}")

    fake_bin = tmp_path / "fake-bin"
    _prepare_fake_tools(fake_bin)
    env = dict(os.environ)
    env[install_env] = str(install_dir)
    env["FAIL_COPY"] = "1" if failure == "copy" else "0"
    env["FAIL_SYNC_AT"] = "1" if failure == "sync" else "2" if failure == "post_sync" else "0"
    env["SYNC_COUNT_FILE"] = str(tmp_path / "sync-count")
    env["REAL_CP"] = shutil.which("cp") or "cp"
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    result = subprocess.run(
        ["bash", str(work / "build.sh")],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, install_dir, target


@pytest.mark.parametrize(("helper_dir", "install_env", "binary_name"), _HELPERS)
@pytest.mark.parametrize("failure", ["copy", "sync"])
def test_precommit_failure_preserves_working_helper_and_cleans_staging(
    tmp_path: Path,
    helper_dir: str,
    install_env: str,
    binary_name: str,
    failure: str,
) -> None:
    result, install_dir, target = _run_installer(
        tmp_path,
        helper_dir,
        install_env,
        binary_name,
        failure=failure,
    )

    assert result.returncode != 0
    assert target.read_bytes() == b"known-good-helper"
    assert not list(install_dir.glob(f".{binary_name}.tmp.*"))


@pytest.mark.parametrize(("helper_dir", "install_env", "binary_name"), _HELPERS)
def test_success_atomically_replaces_helper_with_executable(
    tmp_path: Path,
    helper_dir: str,
    install_env: str,
    binary_name: str,
) -> None:
    result, install_dir, target = _run_installer(
        tmp_path,
        helper_dir,
        install_env,
        binary_name,
        failure=None,
    )

    assert result.returncode == 0, result.stderr
    assert target.read_bytes() == b"complete-new-helper"
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert not list(install_dir.glob(f".{binary_name}.tmp.*"))


@pytest.mark.parametrize(("helper_dir", "install_env", "binary_name"), _HELPERS)
def test_postcommit_directory_sync_failure_is_reported_with_complete_target(
    tmp_path: Path,
    helper_dir: str,
    install_env: str,
    binary_name: str,
) -> None:
    result, install_dir, target = _run_installer(
        tmp_path,
        helper_dir,
        install_env,
        binary_name,
        failure="post_sync",
    )

    assert result.returncode != 0
    assert target.read_bytes() == b"complete-new-helper"
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert not list(install_dir.glob(f".{binary_name}.tmp.*"))


@pytest.mark.parametrize(("helper_dir", "install_env", "binary_name"), _HELPERS)
@pytest.mark.parametrize("target_kind", ["directory", "symlink"])
def test_refuses_unsafe_existing_target_before_staging(
    tmp_path: Path,
    helper_dir: str,
    install_env: str,
    binary_name: str,
    target_kind: str,
) -> None:
    result, install_dir, target = _run_installer(
        tmp_path,
        helper_dir,
        install_env,
        binary_name,
        failure=None,
        existing_target=target_kind,
    )

    assert result.returncode != 0
    assert "install target must be a regular file or absent" in result.stderr
    assert target.is_dir() if target_kind == "directory" else target.is_symlink()
    assert not list(install_dir.glob(f".{binary_name}.tmp.*"))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
@pytest.mark.parametrize(("helper_dir", "install_env", "binary_name"), _HELPERS)
def test_refuses_existing_fifo_target_before_staging(
    tmp_path: Path,
    helper_dir: str,
    install_env: str,
    binary_name: str,
) -> None:
    result, install_dir, target = _run_installer(
        tmp_path,
        helper_dir,
        install_env,
        binary_name,
        failure=None,
        existing_target="fifo",
    )

    assert result.returncode != 0
    assert "install target must be a regular file or absent" in result.stderr
    assert stat.S_ISFIFO(target.lstat().st_mode)
    assert not list(install_dir.glob(f".{binary_name}.tmp.*"))
