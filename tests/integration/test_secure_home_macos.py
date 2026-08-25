"""Live secure-home integration tests — a real ``hdiutil``-created encrypted
APFS volume, the real :data:`DEFAULT_RUNNER` /
:data:`DEFAULT_VOLUME_RUNNER`, and the real ``os.path.ismount``.

Three tests live here: the Phase 1 ``adopt``/``status``/``run`` path against
a volume this file creates by hand; the Phase 2
``init``/``unmount``/``mount``/``run``/``unmount`` round trip, which drives
``secure_home_lifecycle_cli`` and therefore lets the *product code* create,
attach, detach and re-attach a real encrypted image (including a
wrong-passphrase ``mount`` that must fail closed); and a native-APFS-volume
test that exercises ``diskutil apfs unlockVolume -stdinpassphrase`` /
``lockVolume`` through :mod:`_secure_home_volume` against a natively
encrypted volume created inside a throwaway *unencrypted* image container —
the only place the ``DISKUTIL_STDIN_TERMINATOR`` assumption and the
"``diskutil`` accepts a VolumeUUID as the disk argument" assumption are
checked against the real tool, without touching the boot disk's container.

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
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

import pytest

from mordred_hermes.wizard import secure_home_cli, secure_home_lifecycle_cli
from mordred_hermes.wizard._secure_home_paths import (
    BACKING_DISK_IMAGE,
    MODE_BALANCED,
    SecureHomeConfig,
    load_config,
    save_config,
)
from mordred_hermes.wizard._secure_home_probe import (
    DEFAULT_RUNNER,
    UUID_MISMATCH,
    SecureHomeVerificationError,
    verify_home,
    volume_info,
)
from mordred_hermes.wizard._secure_home_volume import (
    DEFAULT_VOLUME_RUNNER,
    DISKUTIL_STDIN_TERMINATOR,
    UNLOCK_FAILED,
    SecureHomeVolumeError,
    lock_native_volume,
    unlock_native_volume,
)

from .._secure_home_fakes import ScriptedPromptIO

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


def test_init_mount_unmount_round_trip_against_a_real_image(tmp_path: Path) -> None:
    """Phase 2: the product code creates, attaches, detaches and re-attaches a real encrypted image.

    Everything stays under ``tmp_path`` — the image, the mount point, the
    pointer config, and the ``home_dir`` the default-path helpers would
    consult — so the developer's real ``~/Library/Application Support`` and
    ``~/.config/hermes-mordred`` are never touched.
    """
    _require_live()

    image_path = tmp_path / "init.sparseimage"
    mount_point = tmp_path / "mnt-init"
    config_path = tmp_path / "config" / "secure-home.json"

    try:
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform=sys.platform,
            prompt_io=ScriptedPromptIO(passwords=[_THROWAWAY_PASSWORD, _THROWAWAY_PASSWORD]),
            image_path=image_path,
            mount_point=mount_point,
            size="32m",
            volume_name=_VOLUME_NAME,
            mode=MODE_BALANCED,
            run=DEFAULT_RUNNER,
            volume_run=DEFAULT_VOLUME_RUNNER,
            ismount=os.path.ismount,
            home_dir=tmp_path,
        )
        assert rc == 0
        assert image_path.is_file()

        recorded = load_config(config_path)
        assert recorded is not None
        assert recorded.backing is not None
        assert recorded.backing.kind == BACKING_DISK_IMAGE
        assert recorded.backing.image_path == image_path
        assert recorded.mode == MODE_BALANCED

        report = secure_home_cli.collect(
            config_path=config_path, platform=sys.platform, run=DEFAULT_RUNNER, ismount=os.path.ismount
        )
        assert report.verified is True
        assert report.backing_kind == BACKING_DISK_IMAGE

        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform=sys.platform,
            run=DEFAULT_RUNNER,
            volume_run=DEFAULT_VOLUME_RUNNER,
            ismount=os.path.ismount,
        )
        assert rc == 0
        assert not os.path.ismount(str(mount_point))

        # Negative check: a wrong passphrase must fail closed — non-zero,
        # nothing mounted, the config untouched — before the real unlock.
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform=sys.platform,
            prompt_io=ScriptedPromptIO(passwords=[_THROWAWAY_PASSWORD + "-wrong"]),
            run=DEFAULT_RUNNER,
            volume_run=DEFAULT_VOLUME_RUNNER,
            ismount=os.path.ismount,
        )
        assert rc == 1
        assert not os.path.ismount(str(mount_point))
        assert load_config(config_path) == recorded

        mount_prompt = ScriptedPromptIO(passwords=[_THROWAWAY_PASSWORD])
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform=sys.platform,
            prompt_io=mount_prompt,
            run=DEFAULT_RUNNER,
            volume_run=DEFAULT_VOLUME_RUNNER,
            ismount=os.path.ismount,
        )
        assert rc == 0
        assert mount_prompt.password_labels == ["Secure-home volume passphrase"]
        assert os.path.ismount(str(mount_point))

        exec_fn = _CapturingExec()
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
        assert env["HERMES_HOME"] == str(mount_point / "hermes-home")

        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform=sys.platform,
            run=DEFAULT_RUNNER,
            volume_run=DEFAULT_VOLUME_RUNNER,
            ismount=os.path.ismount,
        )
        assert rc == 0
        assert not os.path.ismount(str(mount_point))
    finally:
        # Best effort: never leak a mount or a throwaway image, even when an
        # assertion above already failed mid-round-trip.
        _detach(mount_point)
        if image_path.exists():
            image_path.unlink()


# -----------------------------------------------------------------------------
# Native APFS volume: diskutil apfs unlockVolume / lockVolume
# -----------------------------------------------------------------------------
_CONTAINER_VOLUME_NAME = "mordred-sh-container"
_NATIVE_VOLUME_NAME = "mordred-sh-native"
_CREATED_VOLUME_RE = re.compile(r"Created new APFS Volume (disk\d+s\d+)")


def _create_plain_sparseimage(image_path: Path) -> None:
    """An *unencrypted* APFS sparseimage — its synthesized container is the
    throwaway host for the natively encrypted volume, so the boot disk's own
    container is never touched."""
    subprocess.run(
        [
            "hdiutil",
            "create",
            "-size",
            "64m",
            "-type",
            "SPARSE",
            "-fs",
            "APFS",
            "-volname",
            _CONTAINER_VOLUME_NAME,
            str(image_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _attach_plain(image_path: Path, mount_point: Path) -> None:
    subprocess.run(
        ["hdiutil", "attach", str(image_path), "-mountpoint", str(mount_point), "-nobrowse", "-owners", "on"],
        check=True,
        capture_output=True,
        text=True,
    )


def _apfs_container_reference(mount_point: Path) -> str:
    """``diskutil info -plist`` → ``APFSContainerReference`` (e.g. ``disk10``)."""
    result = subprocess.run(
        ["diskutil", "info", "-plist", str(mount_point)], check=True, capture_output=True, text=True
    )
    plist = plistlib.loads(result.stdout.encode())
    reference = plist.get("APFSContainerReference")
    assert isinstance(reference, str) and reference, plist
    return reference


def _add_native_encrypted_volume(container: str) -> str:
    """``diskutil apfs addVolume … -stdinpassphrase -nomount`` → the new volume's disk identifier.

    Uses the same stdin terminator the product code relies on, so a wrong
    assumption there surfaces here first (as a create/unlock mismatch)."""
    result = subprocess.run(
        ["diskutil", "apfs", "addVolume", container, "APFS", _NATIVE_VOLUME_NAME, "-stdinpassphrase", "-nomount"],
        input=_THROWAWAY_PASSWORD + DISKUTIL_STDIN_TERMINATOR,
        check=True,
        capture_output=True,
        text=True,
    )
    match = _CREATED_VOLUME_RE.search(result.stdout)
    assert match is not None, result.stdout
    return match.group(1)


def _volume_uuid_of(disk_identifier: str) -> str:
    result = subprocess.run(["diskutil", "info", "-plist", disk_identifier], check=True, capture_output=True, text=True)
    plist = plistlib.loads(result.stdout.encode())
    volume_uuid = plist.get("VolumeUUID")
    assert isinstance(volume_uuid, str) and volume_uuid, plist
    return volume_uuid


def _delete_native_volume(disk_identifier: str | None) -> None:
    if disk_identifier is None:
        return
    subprocess.run(["diskutil", "apfs", "deleteVolume", disk_identifier], capture_output=True, text=True, check=False)


def test_native_apfs_volume_unlock_and_lock_against_a_throwaway_container(tmp_path: Path) -> None:
    """Phase 2 native path: ``unlock_native_volume``/``lock_native_volume`` against a real
    natively encrypted APFS volume.

    Creation itself is done by hand here (``diskutil apfs addVolume`` needs
    a container the user owns — the throwaway image's — and its
    ``-mountpoint`` is root-only, which is exactly why ``init`` does not
    offer native volumes). Ownership on the new volume is *reported*, not
    asserted: whether a freshly added image-hosted volume honours ownership
    decides if ``adopt`` would accept it, but that is a macOS policy, not
    this code's contract.
    """
    _require_live()

    container_image = tmp_path / "container.sparseimage"
    container_mount = tmp_path / "mnt-container"
    container_mount.mkdir()
    native_mount = tmp_path / "mnt-native"
    native_mount.mkdir()
    new_volume: str | None = None

    _create_plain_sparseimage(container_image)
    try:
        _attach_plain(container_image, container_mount)
        container = _apfs_container_reference(container_mount)
        new_volume = _add_native_encrypted_volume(container)
        volume_uuid = _volume_uuid_of(new_volume)

        # A freshly added encrypted volume may still be unlocked (just not
        # mounted); lock it first so the unlock below is a real unlock.
        try:
            lock_native_volume(volume_uuid, run=DEFAULT_VOLUME_RUNNER)
        except SecureHomeVolumeError as exc:
            assert "lock" in exc.message.casefold(), exc.message  # e.g. "already locked" — acceptable

        # Wrong passphrase first: must fail closed with the UNLOCK_FAILED code
        # and leave nothing mounted.
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            unlock_native_volume(
                volume_uuid, native_mount, passphrase=_THROWAWAY_PASSWORD + "-wrong", run=DEFAULT_VOLUME_RUNNER
            )
        assert exc_info.value.code == UNLOCK_FAILED
        assert not os.path.ismount(str(native_mount))

        unlock_native_volume(volume_uuid, native_mount, passphrase=_THROWAWAY_PASSWORD, run=DEFAULT_VOLUME_RUNNER)
        assert os.path.ismount(str(native_mount))
        info = volume_info(native_mount, run=DEFAULT_RUNNER)
        assert info.volume_uuid is not None
        assert info.volume_uuid.casefold() == volume_uuid.casefold()
        assert info.encryption_this_volume_proper is True
        print(f"[live] native volume ownership_enabled={info.ownership_enabled!r} (adopt requires True)")

        lock_native_volume(volume_uuid, run=DEFAULT_VOLUME_RUNNER)
        assert not os.path.ismount(str(native_mount))
    finally:
        # Newest first: the native volume (which also unmounts it), then the
        # container image, then the file. All best effort — never leak a
        # mount or a throwaway image.
        _detach(native_mount)
        _delete_native_volume(new_volume)
        _detach(container_mount)
        if container_image.exists():
            container_image.unlink()
