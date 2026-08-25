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
``lockVolume`` through :mod:`_secure_home_volume` against a throwaway
image's single APFS volume encrypted *in place* (``diskutil apfs
encryptVolume``) — the only place the ``DISKUTIL_STDIN_TERMINATOR``
assumption and the "``diskutil`` accepts a VolumeUUID as the disk argument"
assumption are checked against the real tool, without touching the boot
disk's container.

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
import subprocess
import sys
import time
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
_NATIVE_VOLUME_NAME = "mordred-sh-native"
_PROPER_ENCRYPTION_TIMEOUT_S = 60.0


def _create_plain_sparseimage(image_path: Path) -> None:
    """An *unencrypted* APFS sparseimage whose single volume is then encrypted
    in place — the boot disk's own container is never touched.

    In place, not "add a second volume": an ``hdiutil``-created APFS image
    container is capped at one volume (``diskutil apfs addVolume`` fails with
    ``-69493 You can't add any more APFS Volumes``), which the first draft
    of this test learned the hard way on 2026-08-25.
    """
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
            _NATIVE_VOLUME_NAME,
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


def _diskutil_info(target: str) -> dict[str, object]:
    result = subprocess.run(["diskutil", "info", "-plist", target], check=True, capture_output=True, text=True)
    parsed = plistlib.loads(result.stdout.encode())
    assert isinstance(parsed, dict), result.stdout
    return parsed


def _volume_identity(mount_point: Path) -> tuple[str, str, str]:
    """``(APFSContainerReference, DeviceIdentifier, VolumeUUID)`` of the mounted volume."""
    plist = _diskutil_info(str(mount_point))
    container, device, volume_uuid = (
        plist.get("APFSContainerReference"),
        plist.get("DeviceIdentifier"),
        plist.get("VolumeUUID"),
    )
    assert isinstance(container, str) and isinstance(device, str) and isinstance(volume_uuid, str), plist
    return container, device, volume_uuid


def _encrypt_volume_in_place(device_identifier: str) -> None:
    """``diskutil apfs encryptVolume <dev> -user disk -stdinpassphrase``.

    Fed with the same stdin terminator the product code relies on for
    ``unlockVolume``, so a wrong assumption there surfaces here first (as an
    encrypt/unlock passphrase mismatch)."""
    subprocess.run(
        ["diskutil", "apfs", "encryptVolume", device_identifier, "-user", "disk", "-stdinpassphrase"],
        input=_THROWAWAY_PASSWORD + DISKUTIL_STDIN_TERMINATOR,
        check=True,
        capture_output=True,
        text=True,
    )


def _wait_until_properly_encrypted(device_identifier: str) -> None:
    """Background conversion is instant with hardware support, but poll anyway."""
    deadline = time.monotonic() + _PROPER_ENCRYPTION_TIMEOUT_S
    while True:
        if _diskutil_info(device_identifier).get("EncryptionThisVolumeProper") is True:
            return
        assert time.monotonic() < deadline, f"{device_identifier} never reported EncryptionThisVolumeProper"
        time.sleep(1.0)


def _detach_container(container_reference: str | None) -> None:
    """Eject the whole image by its synthesized container disk — works even
    while its only volume is locked (so nothing is mounted to detach by path)."""
    if container_reference is None:
        return
    result = subprocess.run(["hdiutil", "detach", container_reference], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        subprocess.run(
            ["hdiutil", "detach", container_reference, "-force"], capture_output=True, text=True, check=False
        )


def test_native_apfs_volume_unlock_and_lock_against_a_throwaway_container(tmp_path: Path) -> None:
    """Phase 2 native path: ``unlock_native_volume``/``lock_native_volume`` against a real
    natively encrypted APFS volume.

    The volume is a throwaway image's single APFS volume, encrypted in place
    by hand (``init`` deliberately does not create native volumes:
    ``diskutil apfs addVolume -mountpoint`` is root-only). What this pins:
    ``diskutil`` accepts the *VolumeUUID* as ``<apfsVolumeDisk>`` for both
    verbs, ``-stdinpassphrase`` reads the ``\\n``-terminated line the product
    code sends, a user-owned ``-mountpoint`` works unprivileged, and a wrong
    passphrase is a clean ``UNLOCK_FAILED``. Ownership on the re-mounted
    volume is *reported*, not asserted: image-backed and external volumes
    re-mounted by ``diskutil`` typically come back ``noowners`` (observed
    ``GlobalPermissionsEnabled: False`` on 2026-08-25), which is exactly why
    ``mount`` re-verifies and relocks — a macOS policy, not this code's
    contract.
    """
    _require_live()

    container_image = tmp_path / "container.sparseimage"
    container_mount = tmp_path / "mnt-container"
    container_mount.mkdir()
    native_mount = tmp_path / "mnt-native"
    native_mount.mkdir()
    container: str | None = None

    _create_plain_sparseimage(container_image)
    try:
        _attach_plain(container_image, container_mount)
        container, device, volume_uuid = _volume_identity(container_mount)
        _encrypt_volume_in_place(device)
        _wait_until_properly_encrypted(device)

        # The freshly encrypted volume is still unlocked and mounted; lock it
        # (product code, by UUID) so the unlock below is a real unlock.
        lock_native_volume(volume_uuid, run=DEFAULT_VOLUME_RUNNER)
        assert not os.path.ismount(str(container_mount))

        # Wrong passphrase first: must fail closed with the UNLOCK_FAILED code,
        # carry the wrong-passphrase hint, and leave nothing mounted.
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            unlock_native_volume(
                volume_uuid, native_mount, passphrase=_THROWAWAY_PASSWORD + "-wrong", run=DEFAULT_VOLUME_RUNNER
            )
        assert exc_info.value.code == UNLOCK_FAILED
        assert "wrong passphrase?" in exc_info.value.message
        assert not os.path.ismount(str(native_mount))

        unlock_native_volume(volume_uuid, native_mount, passphrase=_THROWAWAY_PASSWORD, run=DEFAULT_VOLUME_RUNNER)
        assert os.path.ismount(str(native_mount))
        info = volume_info(native_mount, run=DEFAULT_RUNNER)
        assert info.volume_uuid is not None
        assert info.volume_uuid.casefold() == volume_uuid.casefold()
        assert info.encryption_this_volume_proper is True
        print(f"[live] native volume ownership_enabled={info.ownership_enabled!r} (adopt/mount require True)")

        lock_native_volume(volume_uuid, run=DEFAULT_VOLUME_RUNNER)
        assert not os.path.ismount(str(native_mount))
    finally:
        # Best effort, newest first: any mount by path, then the whole image
        # by its container disk (the volume may be locked, i.e. unmounted),
        # then the file. Never leak a mount or a throwaway image.
        _detach(native_mount)
        _detach(container_mount)
        _detach_container(container)
        if container_image.exists():
            container_image.unlink()
