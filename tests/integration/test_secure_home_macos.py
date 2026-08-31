"""Live secure-home integration test — a real ``hdiutil``-created encrypted
APFS volume, the real :data:`DEFAULT_RUNNER`, and the real
``os.path.ismount``.

Gated by ``MORDRED_LIVE_SECURE_HOME_TEST=1`` (mirrors
``tests/integration/test_keyvault_macos.py``'s ``MORDRED_KEYVAULT_LIVE``
gate) so CI and a plain ``pytest -q`` stay hermetic — creating and mounting
an encrypted volume is slow and needs real Disk Arbitration. Everything
this test touches lives under ``tmp_path``; it never reads or writes
``~/.hermes`` or the real ``~/.config/hermes-mordred/secure-home.json``
(every ``secure_home_cli`` call below passes an explicit ``config_path``
into ``tmp_path``, never :func:`resolve_config_path`).

Run manually:

.. code-block:: bash

   MORDRED_LIVE_SECURE_HOME_TEST=1 pytest -m integration \\
       tests/integration/test_secure_home_macos.py -v
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

import pytest

from mordred_hermes.wizard import secure_home_cli
from mordred_hermes.wizard._secure_home_paths import SecureHomeConfig, load_config, save_config
from mordred_hermes.wizard._secure_home_probe import (
    DEFAULT_RUNNER,
    UUID_MISMATCH,
    SecureHomeVerificationError,
    verify_home,
)

pytestmark = pytest.mark.integration

_LIVE_GATE_ENV = "MORDRED_LIVE_SECURE_HOME_TEST"
_VOLUME_NAME = "mordred-sh-test"
_THROWAWAY_PASSWORD = "mordred-secure-home-itest-throwaway"
_BOGUS_UUID = "00000000-0000-0000-0000-000000000000"


def _require_live() -> None:
    if sys.platform != "darwin":
        pytest.skip(f"{_LIVE_GATE_ENV}=1 requires macOS (found {sys.platform!r})")
    if os.environ.get(_LIVE_GATE_ENV) != "1":
        pytest.skip(f"set {_LIVE_GATE_ENV}=1 to run the live secure-home integration test")


def _create_sparseimage(image_path: Path) -> None:
    """A throwaway 32MB encrypted APFS sparseimage; the password never
    touches argv (fed via ``-stdinpass``)."""
    subprocess.run(
        [
            "hdiutil",
            "create",
            "-size",
            "32m",
            "-fs",
            "APFS",
            "-encryption",
            "AES-256",
            "-stdinpass",
            "-volname",
            _VOLUME_NAME,
            str(image_path),
        ],
        input=_THROWAWAY_PASSWORD,
        text=True,
        check=True,
        capture_output=True,
    )


def _attach(image_path: Path, mount_point: Path) -> None:
    subprocess.run(
        [
            "hdiutil",
            "attach",
            str(image_path),
            "-stdinpass",
            "-mountpoint",
            str(mount_point),
            "-nobrowse",
            "-owners",
            "on",
        ],
        input=_THROWAWAY_PASSWORD,
        text=True,
        check=True,
        capture_output=True,
    )


def _detach(mount_point: Path) -> None:
    """Best-effort detach with a ``-force`` fallback — must never leak a mount,
    even when the test body already failed an assertion."""
    result = subprocess.run(["hdiutil", "detach", str(mount_point)], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        subprocess.run(["hdiutil", "detach", str(mount_point), "-force"], capture_output=True, text=True, check=False)


class _CapturingExec:
    """Stands in for ``os.execvpe`` — records the call instead of replacing
    the process, so the test can assert on ``HERMES_HOME`` without actually
    exec'ing anything."""

    def __init__(self) -> None:
        self.captured: tuple[str, list[str], dict[str, str]] | None = None

    def __call__(self, file: str, args: list[str], env: dict[str, str]) -> NoReturn:
        self.captured = (file, list(args), dict(env))
        return None  # type: ignore[return-value]


def test_adopt_status_run_against_a_real_encrypted_apfs_volume(tmp_path: Path) -> None:
    _require_live()

    image_path = tmp_path / f"{_VOLUME_NAME}.sparseimage"
    mount_point = tmp_path / "mnt"
    mount_point.mkdir()
    config_path = tmp_path / "config" / "secure-home.json"

    _create_sparseimage(image_path)
    try:
        _attach(image_path, mount_point)

        rc = secure_home_cli.adopt(
            mount_point,
            config_path=config_path,
            platform=sys.platform,
            run=DEFAULT_RUNNER,
            ismount=os.path.ismount,
        )
        assert rc == 0
        home = mount_point / "hermes-home"
        assert home.is_dir()

        report = secure_home_cli.collect(
            config_path=config_path, platform=sys.platform, run=DEFAULT_RUNNER, ismount=os.path.ismount
        )
        assert report.verified is True
        assert report.mounted is True

        exec_fn = _CapturingExec()
        # A minimal, hand-built environ (never the real os.environ) so a
        # captured env can never leak real secrets; "/bin/echo" is an
        # absolute path so shutil.which resolves it directly, independent
        # of this trimmed PATH.
        minimal_environ = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path)}
        rc = secure_home_cli.run_command(
            ["/bin/echo"],
            config_path=config_path,
            platform=sys.platform,
            run=DEFAULT_RUNNER,
            ismount=os.path.ismount,
            exec_fn=exec_fn,
            environ=minimal_environ,
        )
        assert rc == 0
        assert exec_fn.captured is not None
        _, _, env = exec_fn.captured
        assert env["HERMES_HOME"] == str(home)

        # Negative check: a config doctored to expect a different UUID must
        # fail closed rather than accept the volume actually mounted there.
        real_config = load_config(config_path)
        assert real_config is not None
        doctored = SecureHomeConfig(
            version=real_config.version, mount_point=real_config.mount_point, volume_uuid=_BOGUS_UUID
        )
        save_config(doctored, tmp_path / "config" / "doctored.json")
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(doctored, run=DEFAULT_RUNNER, ismount=os.path.ismount)
        assert exc_info.value.code == UUID_MISMATCH
    finally:
        _detach(mount_point)
