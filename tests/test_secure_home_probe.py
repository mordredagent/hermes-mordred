"""Tests for ``mordred_hermes.wizard._secure_home_probe``.

``fdesetup``/``diskutil``/``hdiutil`` are fully mocked via the injectable
:class:`SubprocessRunner` — no real subprocess is ever invoked and no real
mount is ever needed (``ismount`` is faked too). Diskutil/hdiutil plist
payloads are built with ``plistlib.dumps(...)`` so the parsing tests exercise
the actual wire format. Covers:

- ``filevault_status``: On / Off / garbled / non-zero exit / raising runner
  all resolve, the last four to ``UNKNOWN`` — it never raises.
- ``volume_info``: the new ``VolumeInfo`` shape (``encryption_this_volume_proper``
  / ``ownership_enabled``), the "legacy Encrypted/FileVault keys are ignored"
  regression, and every invocation/parse failure mode (including a truncated
  plist body, which used to escape as a raw ``ExpatError``).
- ``inspect_mounted_volume``: chain steps 1-3 (symlink-safe mountpoint,
  mounted, diskutil probe) in isolation.
- ``ensure_volume_acceptable``: chain steps 5-8 (APFS filesystem, not a
  boot/system volume, encrypted — native or image-backed via ``hdiutil`` —,
  ownership honored) in isolation, fed hand-built :class:`VolumeInfo` values.
- ``verify_home``: the full success path and every failure code of the
  fail-closed chain, isolated one step at a time (everything before the
  tested step is made to pass), including the new mount/home device
  continuity check.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard._secure_home_paths import SecureHomeConfig
from mordred_hermes.wizard._secure_home_probe import (
    BOOT_VOLUME,
    HOME_MISSING,
    NOT_APFS,
    NOT_ENCRYPTED,
    NOT_MOUNTED,
    OWNERSHIP_DISABLED,
    PROBE_FAILED,
    UNSAFE_HOME,
    UUID_MISMATCH,
    FileVaultState,
    SecureHomeProbeError,
    SecureHomeVerificationError,
    VerifiedHome,
    VolumeInfo,
    attached_image_device,
    backing_image_path,
    ensure_volume_acceptable,
    filevault_status,
    inspect_mounted_volume,
    native_volume_state,
    verify_home,
    verify_mounted_identity,
    volume_info,
)

_UUID = "1956CE7B-0F1B-4CE6-A9E4-BAAAD5CF9E1C"
_OTHER_UUID = "2A6F5D3C-8B1E-4F2A-9C3D-7E8F1A2B3C4D"


# -----------------------------------------------------------------------------
# Fake runners
# -----------------------------------------------------------------------------
class _ScriptedRunner:
    """Returns a fixed ``CompletedProcess`` (or raises) for every call."""

    def __init__(
        self,
        *,
        result: subprocess.CompletedProcess[str] | None = None,
        exc: Exception | None = None,
    ) -> None:
        self._result = result
        self._exc = exc
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        if self._exc is not None:
            raise self._exc
        assert self._result is not None
        return self._result


class _DispatchRunner:
    """Dispatches on ``argv[0]``: diskutil / hdiutil / fdesetup, each scripted independently.

    Mirrors ``TestRun``'s ``_FakeRunner`` in ``tests/test_wizard_secure_home_cli.py``
    but also supports ``hdiutil`` — needed to exercise the image-backed
    encryption gate, which invokes ``hdiutil info -plist`` through the same
    injected runner.
    """

    def __init__(
        self,
        *,
        diskutil_result: subprocess.CompletedProcess[str] | None = None,
        diskutil_exc: Exception | None = None,
        hdiutil_result: subprocess.CompletedProcess[str] | None = None,
        hdiutil_exc: Exception | None = None,
        fdesetup_result: subprocess.CompletedProcess[str] | None = None,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._diskutil_result = diskutil_result
        self._diskutil_exc = diskutil_exc
        self._hdiutil_result = hdiutil_result
        self._hdiutil_exc = hdiutil_exc
        self._fdesetup_result = fdesetup_result

    def __call__(self, argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        if argv[0] == "diskutil":
            if self._diskutil_exc is not None:
                raise self._diskutil_exc
            assert self._diskutil_result is not None
            return self._diskutil_result
        if argv[0] == "hdiutil":
            if self._hdiutil_exc is not None:
                raise self._hdiutil_exc
            assert self._hdiutil_result is not None
            return self._hdiutil_result
        if argv[0] == "fdesetup":
            assert self._fdesetup_result is not None
            return self._fdesetup_result
        raise AssertionError(f"unexpected command: {argv}")


def _completed(
    argv: Sequence[str], stdout: str = "", returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=list(argv), returncode=returncode, stdout=stdout, stderr=stderr)


def _diskutil_plist_result(
    plist: dict[str, Any], *, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    argv = ("diskutil", "info", "-plist", "<mount>")
    return _completed(argv, stdout=plistlib.dumps(plist).decode(), returncode=returncode, stderr=stderr)


def _hdiutil_plist_result(
    plist: dict[str, Any], *, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    argv = ("hdiutil", "info", "-plist")
    return _completed(argv, stdout=plistlib.dumps(plist).decode(), returncode=returncode, stderr=stderr)


def _volume_plist(
    *,
    uuid: str | None = _UUID,
    filesystem: str | None = "apfs",
    mount_point: str | None = None,
    device_node: str | None = "/dev/disk3s2",
    proper: bool | None = True,
    ownership: bool | None = True,
) -> dict[str, Any]:
    """Craft a ``diskutil info -plist`` payload using only the new (v2) keys."""
    plist: dict[str, Any] = {}
    if uuid is not None:
        plist["VolumeUUID"] = uuid
    if filesystem is not None:
        plist["FilesystemType"] = filesystem
    if mount_point is not None:
        plist["MountPoint"] = mount_point
    if device_node is not None:
        plist["DeviceNode"] = device_node
    if proper is not None:
        plist["EncryptionThisVolumeProper"] = proper
    if ownership is not None:
        plist["GlobalPermissionsEnabled"] = ownership
    return plist


def _hdiutil_image(
    dev_entries: Sequence[str], *, encrypted: bool | None, image_path: str | None = None
) -> dict[str, Any]:
    entities: list[dict[str, Any]] = [{"dev-entry": entry} for entry in dev_entries]
    image: dict[str, Any] = {"system-entities": entities}
    if encrypted is not None:
        image["image-encrypted"] = encrypted
    if image_path is not None:
        image["image-path"] = image_path
    return image


def _unused_runner(argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    raise AssertionError(f"subprocess should not have been invoked: {argv}")


def _info(
    *,
    volume_uuid: str | None = _UUID,
    filesystem: str | None = "apfs",
    mount_point: str | None = None,
    device_node: str | None = "/dev/disk3s2",
    encryption_this_volume_proper: bool | None = True,
    ownership_enabled: bool | None = True,
) -> VolumeInfo:
    """A pre-parsed, acceptable-by-default :class:`VolumeInfo` for ``ensure_volume_acceptable`` tests."""
    return VolumeInfo(
        volume_uuid=volume_uuid,
        filesystem=filesystem,
        mount_point=mount_point,
        device_node=device_node,
        encryption_this_volume_proper=encryption_this_volume_proper,
        ownership_enabled=ownership_enabled,
    )


# -----------------------------------------------------------------------------
# filevault_status
# -----------------------------------------------------------------------------
class TestFileVaultStatus:
    def test_on(self) -> None:
        run = _ScriptedRunner(result=_completed(("fdesetup", "status"), stdout="FileVault is On.\n"))
        assert filevault_status(run=run) is FileVaultState.ON

    def test_off(self) -> None:
        run = _ScriptedRunner(result=_completed(("fdesetup", "status"), stdout="FileVault is Off.\n"))
        assert filevault_status(run=run) is FileVaultState.OFF

    def test_garbled_output_is_unknown(self) -> None:
        run = _ScriptedRunner(result=_completed(("fdesetup", "status"), stdout="not a recognizable answer\n"))
        assert filevault_status(run=run) is FileVaultState.UNKNOWN

    def test_nonzero_exit_is_unknown(self) -> None:
        run = _ScriptedRunner(result=_completed(("fdesetup", "status"), stdout="FileVault is On.\n", returncode=1))
        assert filevault_status(run=run) is FileVaultState.UNKNOWN

    def test_oserror_is_unknown(self) -> None:
        run = _ScriptedRunner(exc=OSError("fdesetup not found"))
        assert filevault_status(run=run) is FileVaultState.UNKNOWN

    def test_subprocess_error_is_unknown(self) -> None:
        run = _ScriptedRunner(exc=subprocess.TimeoutExpired(cmd="fdesetup", timeout=10.0))
        assert filevault_status(run=run) is FileVaultState.UNKNOWN

    def test_never_raises(self) -> None:
        run = _ScriptedRunner(exc=RuntimeError("should still be caught by OSError/SubprocessError"))
        with pytest.raises(RuntimeError):
            # Confirms our fake only swallows the documented exception types —
            # an arbitrary RuntimeError is not one of them, so it propagates
            # and filevault_status's "never raises" claim is about
            # OSError/SubprocessError specifically, not literally everything.
            filevault_status(run=run)


# -----------------------------------------------------------------------------
# volume_info
# -----------------------------------------------------------------------------
class TestVolumeInfo:
    def test_full_plist(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "Volumes" / "SecureHermes"
        plist = _volume_plist(mount_point=str(mount_point), device_node="/dev/disk3s2")
        run = _ScriptedRunner(result=_diskutil_plist_result(plist))
        info = volume_info(mount_point, run=run)
        assert info.volume_uuid == _UUID
        assert info.filesystem == "apfs"
        assert info.mount_point == str(mount_point)
        assert info.device_node == "/dev/disk3s2"
        assert info.encryption_this_volume_proper is True
        assert info.ownership_enabled is True

    def test_minimal_plist_all_none(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_diskutil_plist_result({}))
        info = volume_info(tmp_path / "mnt", run=run)
        assert info.volume_uuid is None
        assert info.filesystem is None
        assert info.mount_point is None
        assert info.device_node is None
        assert info.encryption_this_volume_proper is None
        assert info.ownership_enabled is None

    def test_filesystem_falls_back_to_filesystem_name(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_diskutil_plist_result({"FilesystemName": "APFS (Encrypted)"}))
        info = volume_info(tmp_path / "mnt", run=run)
        assert info.filesystem == "APFS (Encrypted)"

    def test_encryption_this_volume_proper_true(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_diskutil_plist_result({"EncryptionThisVolumeProper": True}))
        assert volume_info(tmp_path / "mnt", run=run).encryption_this_volume_proper is True

    def test_encryption_this_volume_proper_false(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_diskutil_plist_result({"EncryptionThisVolumeProper": False}))
        assert volume_info(tmp_path / "mnt", run=run).encryption_this_volume_proper is False

    def test_legacy_encryption_keys_are_ignored(self, tmp_path: Path) -> None:
        """Regression: a FileVault boot volume reports Encryption/FileVault true

        with no ``EncryptionThisVolumeProper`` key at all — those legacy keys
        must NOT be read as a stand-in, or a boot volume would falsely
        "verify" as an independently-encrypted secure home.
        """
        plist = {"Encryption": True, "FileVault": True, "Encrypted": True}
        run = _ScriptedRunner(result=_diskutil_plist_result(plist))
        info = volume_info(tmp_path / "mnt", run=run)
        assert info.encryption_this_volume_proper is None

    def test_ownership_enabled_parsed(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_diskutil_plist_result({"GlobalPermissionsEnabled": True}))
        assert volume_info(tmp_path / "mnt", run=run).ownership_enabled is True

    def test_ownership_disabled_parsed(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_diskutil_plist_result({"GlobalPermissionsEnabled": False}))
        assert volume_info(tmp_path / "mnt", run=run).ownership_enabled is False

    def test_nonzero_exit_raises(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_completed(("diskutil",), returncode=1, stderr="No such volume"))
        with pytest.raises(SecureHomeProbeError, match="No such volume"):
            volume_info(tmp_path / "mnt", run=run)

    def test_oserror_raises(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeProbeError):
            volume_info(tmp_path / "mnt", run=run)

    def test_bad_plist_raises(self, tmp_path: Path) -> None:
        run = _ScriptedRunner(result=_completed(("diskutil",), stdout="not a plist at all"))
        with pytest.raises(SecureHomeProbeError):
            volume_info(tmp_path / "mnt", run=run)

    def test_truncated_plist_raises_probe_error_not_expat_error(self, tmp_path: Path) -> None:
        """Regression: a valid-XML-headed but cut-off body used to escape as ``ExpatError``."""
        full = plistlib.dumps(_volume_plist()).decode()
        truncated = full[: len(full) // 2]
        run = _ScriptedRunner(result=_completed(("diskutil",), stdout=truncated))
        with pytest.raises(SecureHomeProbeError):
            volume_info(tmp_path / "mnt", run=run)

    def test_non_dict_plist_raises(self, tmp_path: Path) -> None:
        stdout = plistlib.dumps(["not", "a", "dict"]).decode()
        run = _ScriptedRunner(result=_completed(("diskutil",), stdout=stdout))
        with pytest.raises(SecureHomeProbeError):
            volume_info(tmp_path / "mnt", run=run)


# -----------------------------------------------------------------------------
# inspect_mounted_volume — chain steps 1-3
# -----------------------------------------------------------------------------
class TestInspectMountedVolume:
    def test_success_returns_volume_info(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        run = _ScriptedRunner(result=_diskutil_plist_result(_volume_plist()))
        info = inspect_mounted_volume(mount_point, run=run, ismount=lambda p: p == str(mount_point))
        assert info.volume_uuid == _UUID

    def test_symlinked_mountpoint_component_is_unsafe(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_mount = tmp_path / "link_mount"
        link_mount.symlink_to(real_dir)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            inspect_mounted_volume(link_mount, run=_unused_runner, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME

    def test_not_mounted(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            inspect_mounted_volume(mount_point, run=_unused_runner, ismount=lambda p: False)
        assert exc_info.value.code == NOT_MOUNTED

    def test_probe_failure_wraps(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        run = _ScriptedRunner(exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            inspect_mounted_volume(mount_point, run=run, ismount=lambda p: True)
        assert exc_info.value.code == PROBE_FAILED


# -----------------------------------------------------------------------------
# ensure_volume_acceptable — chain steps 5-8
# -----------------------------------------------------------------------------
class TestEnsureVolumeAcceptableFilesystem:
    def test_apfs_accepted(self, tmp_path: Path) -> None:
        ensure_volume_acceptable(_info(filesystem="apfs"), tmp_path / "mnt", run=_unused_runner)

    def test_case_sensitive_apfs_accepted(self, tmp_path: Path) -> None:
        ensure_volume_acceptable(_info(filesystem="Case-sensitive APFS"), tmp_path / "mnt", run=_unused_runner)

    def test_hfs_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(filesystem="hfs"), tmp_path / "mnt", run=_unused_runner)
        assert exc_info.value.code == NOT_APFS

    def test_unknown_filesystem_fails_closed(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(filesystem=None), tmp_path / "mnt", run=_unused_runner)
        assert exc_info.value.code == NOT_APFS

    def test_substring_trick_rejected(self, tmp_path: Path) -> None:
        """``"xapfsx"`` contains "apfs" as a substring but must not match by casefold membership."""
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(filesystem="xapfsx"), tmp_path / "mnt", run=_unused_runner)
        assert exc_info.value.code == NOT_APFS


class TestEnsureVolumeAcceptableBootVolume:
    def test_diskutil_reported_root_is_boot_volume(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(mount_point="/"), tmp_path / "mnt", run=_unused_runner)
        assert exc_info.value.code == BOOT_VOLUME

    def test_diskutil_reported_system_volumes_prefix_is_boot_volume(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(mount_point="/System/Volumes/Data"), tmp_path / "mnt", run=_unused_runner)
        assert exc_info.value.code == BOOT_VOLUME

    def test_configured_mount_point_root_is_boot_volume(self) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(mount_point=None), Path("/"), run=_unused_runner)
        assert exc_info.value.code == BOOT_VOLUME

    def test_configured_mount_point_system_volumes_prefix_is_boot_volume(self) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(mount_point=None), Path("/System/Volumes/SecureHermes"), run=_unused_runner)
        assert exc_info.value.code == BOOT_VOLUME

    def test_ordinary_mount_point_is_not_boot_volume(self, tmp_path: Path) -> None:
        ensure_volume_acceptable(_info(mount_point=str(tmp_path / "mnt")), tmp_path / "mnt", run=_unused_runner)


class TestEnsureVolumeAcceptableEncryption:
    def test_native_encrypted_skips_hdiutil(self, tmp_path: Path) -> None:
        """``EncryptionThisVolumeProper: True`` passes without ever calling ``hdiutil``."""
        run = _DispatchRunner()  # any hdiutil call raises AssertionError inside the fake
        ensure_volume_acceptable(_info(encryption_this_volume_proper=True), tmp_path / "mnt", run=run)
        assert all(call[0] != "hdiutil" for call in run.calls)

    def test_image_backed_encrypted_proper_absent(self, tmp_path: Path) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result({"images": [_hdiutil_image(["/dev/disk3s2"], encrypted=True)]})
        )
        ensure_volume_acceptable(
            _info(encryption_this_volume_proper=None, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
        )

    def test_image_backed_encrypted_proper_false(self, tmp_path: Path) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result({"images": [_hdiutil_image(["/dev/disk3s2"], encrypted=True)]})
        )
        ensure_volume_acceptable(
            _info(encryption_this_volume_proper=False, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
        )

    def test_image_backed_unencrypted(self, tmp_path: Path) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result({"images": [_hdiutil_image(["/dev/disk3s2"], encrypted=False)]})
        )
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(
                _info(encryption_this_volume_proper=None, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
            )
        assert exc_info.value.code == NOT_ENCRYPTED

    def test_image_backed_missing_encrypted_key_is_unencrypted(self, tmp_path: Path) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result({"images": [_hdiutil_image(["/dev/disk3s2"], encrypted=None)]})
        )
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(
                _info(encryption_this_volume_proper=None, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
            )
        assert exc_info.value.code == NOT_ENCRYPTED

    def test_no_matching_image_is_unencrypted(self, tmp_path: Path) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result({"images": [_hdiutil_image(["/dev/disk7s1"], encrypted=True)]})
        )
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(
                _info(encryption_this_volume_proper=None, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
            )
        assert exc_info.value.code == NOT_ENCRYPTED

    def test_no_images_at_all_is_unencrypted(self, tmp_path: Path) -> None:
        run = _DispatchRunner(hdiutil_result=_hdiutil_plist_result({"images": []}))
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(
                _info(encryption_this_volume_proper=None, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
            )
        assert exc_info.value.code == NOT_ENCRYPTED

    def test_whole_disk_match(self, tmp_path: Path) -> None:
        """``/dev/disk9`` (whole-disk) listed while the volume is ``/dev/disk9s1``."""
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result({"images": [_hdiutil_image(["/dev/disk9"], encrypted=True)]})
        )
        ensure_volume_acceptable(
            _info(encryption_this_volume_proper=None, device_node="/dev/disk9s1"), tmp_path / "mnt", run=run
        )

    def test_no_device_node_skips_hdiutil_and_is_unencrypted(self, tmp_path: Path) -> None:
        run = _DispatchRunner()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(
                _info(encryption_this_volume_proper=None, device_node=None), tmp_path / "mnt", run=run
            )
        assert exc_info.value.code == NOT_ENCRYPTED
        assert run.calls == []

    def test_hdiutil_nonzero_exit_is_probe_failed(self, tmp_path: Path) -> None:
        run = _DispatchRunner(hdiutil_result=_completed(("hdiutil", "info", "-plist"), returncode=1, stderr="boom"))
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(
                _info(encryption_this_volume_proper=None, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
            )
        assert exc_info.value.code == PROBE_FAILED
        assert "backing disk image" in exc_info.value.message

    def test_hdiutil_oserror_is_probe_failed(self, tmp_path: Path) -> None:
        run = _DispatchRunner(hdiutil_exc=OSError("hdiutil not found"))
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(
                _info(encryption_this_volume_proper=None, device_node="/dev/disk3s2"), tmp_path / "mnt", run=run
            )
        assert exc_info.value.code == PROBE_FAILED


class TestEnsureVolumeAcceptableOwnership:
    def test_ownership_enabled_accepted(self, tmp_path: Path) -> None:
        ensure_volume_acceptable(_info(ownership_enabled=True), tmp_path / "mnt", run=_unused_runner)

    def test_ownership_disabled_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(ownership_enabled=False), tmp_path / "mnt", run=_unused_runner)
        assert exc_info.value.code == OWNERSHIP_DISABLED
        assert "hdiutil attach -owners on" in exc_info.value.message

    def test_ownership_unknown_fails_closed(self, tmp_path: Path) -> None:
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            ensure_volume_acceptable(_info(ownership_enabled=None), tmp_path / "mnt", run=_unused_runner)
        assert exc_info.value.code == OWNERSHIP_DISABLED


# -----------------------------------------------------------------------------
# verify_home — the full fail-closed chain
# -----------------------------------------------------------------------------
_VERIFY_UUID = _UUID


def _make_mount(tmp_path: Path, *, with_home: bool = True) -> Path:
    mount_point = tmp_path / "Volumes" / "SecureHermes"
    mount_point.mkdir(parents=True)
    if with_home:
        home = mount_point / "hermes-home"
        home.mkdir()
        home.chmod(0o700)
    return mount_point


def _good_run(
    *,
    uuid: str | None = _VERIFY_UUID,
    filesystem: str | None = "apfs",
    proper: bool | None = True,
    ownership: bool | None = True,
) -> _ScriptedRunner:
    plist = _volume_plist(
        uuid=uuid, filesystem=filesystem, device_node="/dev/disk3s2", proper=proper, ownership=ownership
    )
    return _ScriptedRunner(result=_diskutil_plist_result(plist))


class TestVerifyHomeSuccess:
    def test_success_returns_verified_home(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        result = verify_home(config, run=run, ismount=lambda p: p == str(mount_point))
        assert result == VerifiedHome(
            home=mount_point / "hermes-home",
            mount_point=mount_point,
            volume_uuid=_VERIFY_UUID,
            device_node="/dev/disk3s2",
        )

    def test_uuid_case_insensitive_match_succeeds(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID.lower())
        run = _good_run(uuid=_VERIFY_UUID.upper())
        result = verify_home(config, run=run, ismount=lambda p: True)
        assert result.volume_uuid == _VERIFY_UUID.lower()

    def test_require_home_false_skips_home_check(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path, with_home=False)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        result = verify_home(config, run=run, ismount=lambda p: True, require_home=False)
        assert result.home == mount_point / "hermes-home"
        assert not result.home.exists()


class TestVerifyHomeFailures:
    def test_mount_point_symlink_component_is_unsafe(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_mount = tmp_path / "link_mount"
        link_mount.symlink_to(real_dir)
        config = SecureHomeConfig(version=1, mount_point=link_mount, volume_uuid=_VERIFY_UUID)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=_unused_runner, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME

    def test_not_mounted_exact_message(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "Volumes" / "SecureHermes"
        mount_point.mkdir(parents=True)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=_unused_runner, ismount=lambda p: False)
        assert exc_info.value.code == NOT_MOUNTED
        assert "Secure Hermes home is locked. Unlock it to continue." in str(exc_info.value)

    def test_probe_failure_wraps(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _ScriptedRunner(exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == PROBE_FAILED

    def test_uuid_mismatch_exact_message(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(uuid=_OTHER_UUID)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UUID_MISMATCH
        assert "A different volume is mounted at the configured path." in str(exc_info.value)

    def test_uuid_absent_is_mismatch(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(uuid=None)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UUID_MISMATCH

    def test_uuid_unparsable_found_value_is_mismatch(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(uuid="not-a-uuid-at-all")
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UUID_MISMATCH

    def test_not_apfs(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(filesystem="hfs")
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == NOT_APFS

    def test_boot_volume(self, tmp_path: Path) -> None:
        mount_point = Path("/")
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == BOOT_VOLUME

    def test_encrypted_false_fails_closed(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(proper=False)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == NOT_ENCRYPTED

    def test_encrypted_unknown_fails_closed(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(proper=None)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == NOT_ENCRYPTED

    def test_ownership_disabled(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(ownership=False)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == OWNERSHIP_DISABLED

    def test_home_missing(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path, with_home=False)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == HOME_MISSING

    def test_home_is_symlink(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path, with_home=False)
        real_home = tmp_path / "real_home"
        real_home.mkdir()
        (mount_point / "hermes-home").symlink_to(real_home)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME

    def test_home_group_writable(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        (mount_point / "hermes-home").chmod(0o770)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME

    def test_home_other_writable(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        (mount_point / "hermes-home").chmod(0o707)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME

    def test_home_not_a_directory(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path, with_home=False)
        (mount_point / "hermes-home").write_text("not a directory")
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME

    def test_home_not_on_verified_volume(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Device continuity: a nested mount/firmlink at ``hermes-home`` must be refused.

        ``_verify_same_device`` is the only user of ``os.lstat`` (the bare
        function, not ``Path.lstat``) in this module, so faking it only for
        the exact ``mount_point`` argument is safe and leaves every other
        symlink/ownership check (which go through ``Path.lstat`` ->
        ``os.stat``) untouched.
        """
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()

        real_lstat = os.lstat

        class _FakeStat:
            def __init__(self, st_dev: int) -> None:
                self.st_dev = st_dev

        def fake_lstat(path: object, *args: object, **kwargs: object) -> object:
            if os.fspath(path) == str(mount_point):  # type: ignore[arg-type]
                real = real_lstat(path)  # type: ignore[arg-type]
                return _FakeStat(real.st_dev + 1)
            return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "lstat", fake_lstat)

        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_home(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME
        assert "not on the verified volume" in exc_info.value.message


# -----------------------------------------------------------------------------
# backing_image_path
# -----------------------------------------------------------------------------
class TestBackingImagePath:
    def test_found_by_exact_dev_entry(self) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result(
                {"images": [_hdiutil_image(["/dev/disk3s2"], encrypted=True, image_path="/tmp/vault.sparseimage")]}
            )
        )
        assert backing_image_path("/dev/disk3s2", run=run) == Path("/tmp/vault.sparseimage")

    def test_found_by_whole_disk_match(self) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result(
                {"images": [_hdiutil_image(["/dev/disk9"], encrypted=True, image_path="/tmp/vault.sparseimage")]}
            )
        )
        assert backing_image_path("/dev/disk9s1", run=run) == Path("/tmp/vault.sparseimage")

    def test_not_image_backed_returns_none(self) -> None:
        run = _DispatchRunner(hdiutil_result=_hdiutil_plist_result({"images": []}))
        assert backing_image_path("/dev/disk3s2", run=run) is None

    def test_matched_image_without_image_path_returns_none(self) -> None:
        run = _DispatchRunner(
            hdiutil_result=_hdiutil_plist_result({"images": [_hdiutil_image(["/dev/disk3s2"], encrypted=True)]})
        )
        assert backing_image_path("/dev/disk3s2", run=run) is None

    def test_hdiutil_failure_raises(self) -> None:
        run = _DispatchRunner(hdiutil_exc=OSError("hdiutil not found"))
        with pytest.raises(SecureHomeProbeError):
            backing_image_path("/dev/disk3s2", run=run)

    def test_hdiutil_nonzero_exit_raises(self) -> None:
        run = _DispatchRunner(hdiutil_result=_completed(("hdiutil", "info", "-plist"), returncode=1, stderr="boom"))
        with pytest.raises(SecureHomeProbeError):
            backing_image_path("/dev/disk3s2", run=run)


# -----------------------------------------------------------------------------
# verify_mounted_identity — chain steps 1-4 only
# -----------------------------------------------------------------------------
class TestAttachedImageDevice:
    """MEDIUM-3: is the secure volume live *somewhere*, not just at our path?"""

    @staticmethod
    def _entities(entries: Sequence[tuple[str, str | None]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for dev_entry, mount_point in entries:
            entity: dict[str, Any] = {"dev-entry": dev_entry}
            if mount_point is not None:
                entity["mount-point"] = mount_point
            out.append(entity)
        return out

    def _runner(self, images: list[dict[str, Any]]) -> _DispatchRunner:
        return _DispatchRunner(hdiutil_result=_hdiutil_plist_result({"images": images}))

    def test_finds_the_whole_disk_node_and_the_mount_points(self) -> None:
        run = self._runner(
            [
                {
                    "image-path": "/img/secure.sparseimage",
                    "system-entities": self._entities(
                        [("/dev/disk9", None), ("/dev/disk9s1", "/Volumes/HermesSecure")]
                    ),
                }
            ]
        )
        found = attached_image_device(Path("/img/secure.sparseimage"), run=run)
        assert found is not None
        assert found.device_node == "/dev/disk9"
        assert found.mount_points == ("/Volumes/HermesSecure",)

    def test_falls_back_to_the_first_entity_when_all_are_mounted(self) -> None:
        run = self._runner(
            [{"image-path": "/img/s.sparseimage", "system-entities": self._entities([("/dev/disk9s1", "/Volumes/X")])}]
        )
        found = attached_image_device(Path("/img/s.sparseimage"), run=run)
        assert found is not None
        assert found.device_node == "/dev/disk9s1"

    def test_matches_across_a_symlinked_path_spelling(self, tmp_path: Path) -> None:
        """``/tmp/x`` and ``/private/tmp/x`` are one file under two names."""
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        image = real_dir / "s.sparseimage"
        image.write_bytes(b"x")
        link_dir = tmp_path / "link"
        link_dir.symlink_to(real_dir)

        run = self._runner([{"image-path": str(image), "system-entities": self._entities([("/dev/disk9", None)])}])
        found = attached_image_device(link_dir / "s.sparseimage", run=run)
        assert found is not None
        assert found.device_node == "/dev/disk9"

    def test_attached_but_not_mounted_has_no_mount_points(self) -> None:
        run = self._runner(
            [{"image-path": "/img/s.sparseimage", "system-entities": self._entities([("/dev/disk9", None)])}]
        )
        found = attached_image_device(Path("/img/s.sparseimage"), run=run)
        assert found is not None
        assert found.mount_points == ()

    def test_not_attached_is_none(self) -> None:
        run = self._runner(
            [{"image-path": "/other.sparseimage", "system-entities": self._entities([("/dev/disk9", None)])}]
        )
        assert attached_image_device(Path("/img/s.sparseimage"), run=run) is None

    @pytest.mark.parametrize(
        "images",
        [
            [],
            ["not a dict"],
            [{"image-path": "/img/s.sparseimage"}],  # no system-entities
            [{"image-path": "/img/s.sparseimage", "system-entities": "nope"}],
            [{"image-path": "/img/s.sparseimage", "system-entities": [{"no-dev-entry": 1}]}],
            [{"system-entities": [{"dev-entry": "/dev/disk9"}]}],  # no image-path
        ],
    )
    def test_malformed_shapes_are_none_not_a_crash(self, images: list[Any]) -> None:
        assert attached_image_device(Path("/img/s.sparseimage"), run=self._runner(images)) is None

    def test_images_key_absent_is_none(self) -> None:
        run = _DispatchRunner(hdiutil_result=_hdiutil_plist_result({}))
        assert attached_image_device(Path("/img/s.sparseimage"), run=run) is None

    def test_hdiutil_failure_raises(self) -> None:
        run = _DispatchRunner(hdiutil_result=_completed(("hdiutil", "info", "-plist"), returncode=1, stderr="boom"))
        with pytest.raises(SecureHomeProbeError):
            attached_image_device(Path("/img/s.sparseimage"), run=run)

    def test_hdiutil_missing_raises(self) -> None:
        run = _DispatchRunner(hdiutil_exc=OSError("hdiutil not found"))
        with pytest.raises(SecureHomeProbeError):
            attached_image_device(Path("/img/s.sparseimage"), run=run)


class TestNativeVolumeState:
    def test_unlocked_volume_reports_its_mount_point(self) -> None:
        run = _DispatchRunner(
            diskutil_result=_diskutil_plist_result({"Locked": False, "MountPoint": "/Volumes/Elsewhere"})
        )
        assert native_volume_state(_UUID, run=run) == (False, "/Volumes/Elsewhere")
        assert run.calls == [("diskutil", "info", "-plist", _UUID)]

    def test_locked_volume(self) -> None:
        run = _DispatchRunner(diskutil_result=_diskutil_plist_result({"Locked": True, "MountPoint": ""}))
        assert native_volume_state(_UUID, run=run) == (True, None)

    def test_missing_keys_are_none(self) -> None:
        run = _DispatchRunner(diskutil_result=_diskutil_plist_result({}))
        assert native_volume_state(_UUID, run=run) == (None, None)

    def test_non_boolean_locked_is_none(self) -> None:
        run = _DispatchRunner(diskutil_result=_diskutil_plist_result({"Locked": "yes"}))
        assert native_volume_state(_UUID, run=run) == (None, None)

    def test_volume_not_present_is_an_answer_not_an_error(self) -> None:
        """``diskutil info <unknown uuid>`` exits non-zero; that means "no such volume"."""
        run = _DispatchRunner(diskutil_result=_completed(("diskutil",), returncode=1, stderr="Could not find disk"))
        assert native_volume_state(_UUID, run=run) == (None, None)

    def test_invocation_failure_still_raises(self) -> None:
        run = _DispatchRunner(diskutil_exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeProbeError):
            native_volume_state(_UUID, run=run)

    def test_unparsable_output_raises(self) -> None:
        run = _DispatchRunner(diskutil_result=_completed(("diskutil",), stdout="not a plist"))
        with pytest.raises(SecureHomeProbeError):
            native_volume_state(_UUID, run=run)


class TestVerifyMountedIdentity:
    def test_success_returns_volume_info(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run()
        info = verify_mounted_identity(config, run=run, ismount=lambda p: True)
        assert isinstance(info, VolumeInfo)
        assert info.volume_uuid == _VERIFY_UUID

    def test_symlinked_mountpoint_component_is_unsafe(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_mount = tmp_path / "link_mount"
        link_mount.symlink_to(real_dir)
        config = SecureHomeConfig(version=1, mount_point=link_mount, volume_uuid=_VERIFY_UUID)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_mounted_identity(config, run=_unused_runner, ismount=lambda p: True)
        assert exc_info.value.code == UNSAFE_HOME

    def test_not_mounted_propagates(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "Volumes" / "SecureHermes"
        mount_point.mkdir(parents=True)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_mounted_identity(config, run=_unused_runner, ismount=lambda p: False)
        assert exc_info.value.code == NOT_MOUNTED

    def test_uuid_mismatch_propagates(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(uuid=_OTHER_UUID)
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_mounted_identity(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == UUID_MISMATCH

    def test_probe_failure_propagates(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _ScriptedRunner(exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeVerificationError) as exc_info:
            verify_mounted_identity(config, run=run, ismount=lambda p: True)
        assert exc_info.value.code == PROBE_FAILED

    def test_does_not_call_ensure_volume_acceptable(self, tmp_path: Path) -> None:
        """Identity-only: a non-APFS, unencrypted, noowners volume with the right UUID still passes.

        ``ensure_volume_acceptable`` (steps 5-8) is a separate call the
        ``unmount`` CLI path must never make — it would refuse to unmount a
        volume that fails acceptance for reasons unrelated to "is this really
        the configured volume".
        """
        mount_point = _make_mount(tmp_path)
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_VERIFY_UUID)
        run = _good_run(filesystem="hfs", proper=False, ownership=False)
        info = verify_mounted_identity(config, run=run, ismount=lambda p: True)
        assert info.filesystem == "hfs"
        assert info.encryption_this_volume_proper is False
        assert info.ownership_enabled is False
