"""Tests for ``mordred_hermes.wizard.secure_home_cli``.

Every subprocess call, mount check, exec, and PATH lookup is injected — no
real ``diskutil``/``fdesetup``/``hdiutil`` runs, no real volume is ever
mounted, and no real process is ever exec'd. Diskutil/hdiutil plist payloads
are built with ``plistlib.dumps`` (mirrors ``tests/test_secure_home_probe.py``)
so the parsing path is exercised for real, and the fake runner dispatches on
``argv[0]`` the same way ``tests/test_secure_home_probe.py``'s
``_DispatchRunner`` does.

The identity chain now judges encryption from ``EncryptionThisVolumeProper``
*or* a backing ``hdiutil``-reported encrypted disk image (see
``_secure_home_probe`` module docstring) — the legacy ``Encrypted``/
``FileVault``/``Encryption`` plist keys are never consulted, and
``volume_uuid`` is validated as a real UUID at construction time. Covers
``status`` (collect/render/JSON, including the mounted-vs-verified
regression where a symlinked mountpoint used to falsely report "mounted"),
``adopt`` (happy path, every refusal, and the late-``save_config``-failure
rollback), ``run`` (happy path, ``which``/exec resolution, poisoned-env
refusals, and exec failure mapping), and the argparse delegation wiring in
both ``_secure_home_parsers`` and ``secure_home_cli.cli_*``.
"""

from __future__ import annotations

import argparse
import json
import plistlib
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mordred_hermes.wizard import _secure_home_parsers, secure_home_cli
from mordred_hermes.wizard._secure_home_paths import SecureHomeConfig, load_config, save_config
from mordred_hermes.wizard._secure_home_probe import NOT_MOUNTED, UNSAFE_HOME

_UUID = "ABCD1234-0000-0000-0000-000000000000"
_OTHER_UUID = "FFFFFFFF-0000-0000-0000-000000000000"


# -----------------------------------------------------------------------------
# Fakes
# -----------------------------------------------------------------------------
class _FakeRunner:
    """Dispatches on ``argv[0]`` — fdesetup / diskutil / hdiutil — each
    scripted independently.

    Mirrors ``tests/test_secure_home_probe.py``'s ``_DispatchRunner``: the
    source now needs all three tools (``hdiutil`` for the image-backed
    encryption gate), so a fake that only knew ``fdesetup``/``diskutil``
    can no longer stand in for the real dispatch.
    """

    def __init__(
        self,
        *,
        filevault_stdout: str = "FileVault is On.\n",
        diskutil_result: subprocess.CompletedProcess[str] | None = None,
        diskutil_exc: Exception | None = None,
        hdiutil_result: subprocess.CompletedProcess[str] | None = None,
        hdiutil_exc: Exception | None = None,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._filevault_stdout = filevault_stdout
        self._diskutil_result = diskutil_result
        self._diskutil_exc = diskutil_exc
        self._hdiutil_result = hdiutil_result
        self._hdiutil_exc = hdiutil_exc

    def __call__(self, argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        if argv[0] == "fdesetup":
            return subprocess.CompletedProcess(args=list(argv), returncode=0, stdout=self._filevault_stdout, stderr="")
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
        raise AssertionError(f"unexpected command: {argv}")


def _unused_runner(argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    raise AssertionError(f"subprocess should not have been invoked: {argv}")


def _unused_ismount(path: str) -> bool:
    raise AssertionError(f"ismount should not have been called: {path}")


def _diskutil_result(
    plist: dict[str, Any], *, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    argv = ("diskutil", "info", "-plist", "<mount>")
    return subprocess.CompletedProcess(
        args=list(argv), returncode=returncode, stdout=plistlib.dumps(plist).decode(), stderr=stderr
    )


def _hdiutil_image(dev_entries: Sequence[str], *, encrypted: bool | None) -> dict[str, Any]:
    entities: list[dict[str, Any]] = [{"dev-entry": entry} for entry in dev_entries]
    image: dict[str, Any] = {"system-entities": entities}
    if encrypted is not None:
        image["image-encrypted"] = encrypted
    return image


def _hdiutil_result(images: Sequence[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
    argv = ("hdiutil", "info", "-plist")
    return subprocess.CompletedProcess(
        args=list(argv), returncode=0, stdout=plistlib.dumps({"images": list(images)}).decode(), stderr=""
    )


def _good_plist(
    mount_point: Path,
    *,
    uuid: str | None = _UUID,
    filesystem: str | None = "apfs",
    device_node: str | None = "/dev/disk3s2",
    reported_mount_point: str | None = None,
    proper: bool | None = True,
    ownership: bool | None = True,
) -> dict[str, Any]:
    """The canonical "good volume" ``diskutil info -plist`` payload.

    Every negative test overrides exactly the one field it's exercising, so
    each refusal is attributable to that field alone.
    """
    plist: dict[str, Any] = {
        "MountPoint": reported_mount_point if reported_mount_point is not None else str(mount_point)
    }
    if uuid is not None:
        plist["VolumeUUID"] = uuid
    if filesystem is not None:
        plist["FilesystemType"] = filesystem
    if device_node is not None:
        plist["DeviceNode"] = device_node
    if proper is not None:
        plist["EncryptionThisVolumeProper"] = proper
    if ownership is not None:
        plist["GlobalPermissionsEnabled"] = ownership
    return plist


class _FakeExec:
    """Records the exec call instead of replacing the process.

    Violates the real ``NoReturn`` contract on purpose (a fake exec must
    hand control back to the caller so the test can assert on it) — tests
    are outside the mypy --strict surface.
    """

    def __init__(self, *, raise_not_found: bool = False, raise_permission: bool = False) -> None:
        self.captured: tuple[str, list[str], dict[str, str]] | None = None
        self._raise_not_found = raise_not_found
        self._raise_permission = raise_permission

    def __call__(self, file: str, args: list[str], env: dict[str, str]) -> NoReturn:
        if self._raise_not_found:
            raise FileNotFoundError(file)
        if self._raise_permission:
            raise PermissionError(file)
        self.captured = (file, list(args), dict(env))
        return None  # type: ignore[return-value]


def _fake_which(prefix: str = "/resolved") -> Any:
    """A ``which`` that always resolves, prefixing the command name."""

    def which(cmd: str, path: str | None = None) -> str | None:
        return f"{prefix}/{cmd}"

    return which


def _which_none(cmd: str, path: str | None = None) -> str | None:
    return None


def _make_mount(tmp_path: Path, name: str = "mnt") -> Path:
    mount_point = tmp_path / name
    mount_point.mkdir()
    return mount_point


def _write_config(config_path: Path, config: SecureHomeConfig) -> None:
    save_config(config, config_path)


# -----------------------------------------------------------------------------
# status
# -----------------------------------------------------------------------------
class TestStatus:
    def test_not_configured_hints_present(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        run = _FakeRunner()
        rc = secure_home_cli.status(
            config_path=tmp_path / "missing.json", platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "configured   : no" in out
        assert "hermes-mordred secure-home adopt" in out
        assert "FileVault alone (Standard) is enough" in out

    def test_configured_and_verified(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        home = mount_point / "hermes-home"
        home.mkdir()
        home.chmod(0o700)
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_UUID)
        _write_config(config_path, config)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        report = secure_home_cli.collect(
            config_path=config_path, platform="darwin", run=run, ismount=lambda p: p == str(mount_point)
        )
        assert report.platform_supported is True
        assert report.configured is True
        assert report.config_error is None
        assert report.filevault == "on"
        assert report.mount_point == str(mount_point)
        assert report.volume_uuid == _UUID
        assert report.home_path == str(home)
        assert report.mounted is True
        assert report.verified is True
        assert report.verification_code is None
        assert report.verification_error is None

        text = secure_home_cli.render_text(report)
        assert "identity     : verified" in text
        assert "(mounted)" in text

        # JSON round-trip.
        assert json.loads(secure_home_cli.render_json(report)) == report.to_dict()

    def test_configured_but_locked(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"  # never created -> definitely "not mounted"
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_UUID)
        _write_config(config_path, config)
        run = _FakeRunner()

        report = secure_home_cli.collect(config_path=config_path, platform="darwin", run=run, ismount=lambda p: False)
        assert report.configured is True
        assert report.verified is False
        assert report.mounted is False
        assert report.verification_code == NOT_MOUNTED
        assert report.verification_error is not None

    def test_symlinked_mountpoint_reports_not_mounted(self, tmp_path: Path) -> None:
        """Regression: a symlinked MOUNTPOINT used to make ``mounted`` lie ``True``.

        ``verify_home`` refuses the symlink *before* ever calling ``ismount``,
        but ``mounted`` is probed directly and independently — so a fake
        ``ismount`` that reports "not mounted" for the symlinked path must
        make ``mounted`` come back ``False``, not be silently skipped.
        """
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_mount = tmp_path / "link_mount"
        link_mount.symlink_to(real_dir)
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = SecureHomeConfig(version=1, mount_point=link_mount, volume_uuid=_UUID)
        _write_config(config_path, config)
        run = _FakeRunner()

        report = secure_home_cli.collect(config_path=config_path, platform="darwin", run=run, ismount=lambda p: False)
        assert report.mounted is False
        assert report.verified is False
        assert report.verification_code == UNSAFE_HOME

    def test_mounted_for_status_oserror_is_none(self, tmp_path: Path) -> None:
        """``_mounted_for_status`` fails closed to ``None`` (not a crash) on a raising ``ismount``."""

        def raising_ismount(path: str) -> bool:
            raise OSError("boom")

        assert secure_home_cli._mounted_for_status(tmp_path / "mnt", raising_ismount) is None

    def test_render_text_unknown_mount_state(self, tmp_path: Path) -> None:
        report = secure_home_cli.SecureHomeStatusReport(
            platform_supported=True,
            configured=True,
            config_path=str(tmp_path / "cfg.json"),
            config_error=None,
            filevault="on",
            mount_point=str(tmp_path / "mnt"),
            volume_uuid=_UUID,
            home_path=str(tmp_path / "mnt" / "hermes-home"),
            mounted=None,
            verified=True,
            verification_code=None,
            verification_error=None,
        )
        assert "(unknown)" in secure_home_cli.render_text(report)

    def test_render_text_failed_variant_contains_code_and_message(self, tmp_path: Path) -> None:
        report = secure_home_cli.SecureHomeStatusReport(
            platform_supported=True,
            configured=True,
            config_path=str(tmp_path / "cfg.json"),
            config_error=None,
            filevault="on",
            mount_point=str(tmp_path / "mnt"),
            volume_uuid=_UUID,
            home_path=str(tmp_path / "mnt" / "hermes-home"),
            mounted=True,
            verified=False,
            verification_code="SOME_CODE",
            verification_error="some descriptive failure",
        )
        text = secure_home_cli.render_text(report)
        assert "SOME_CODE" in text
        assert "some descriptive failure" in text

    def test_config_unreadable(self, tmp_path: Path) -> None:
        config_path = tmp_path / "cfg" / "secure-home.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("not json at all", encoding="utf-8")
        run = _FakeRunner()

        report = secure_home_cli.collect(config_path=config_path, platform="darwin", run=run, ismount=lambda p: True)
        assert report.configured is False
        assert report.config_error is not None

        rc = secure_home_cli.status(config_path=config_path, platform="darwin", run=run, ismount=lambda p: True)
        assert rc == 0

    def test_config_non_utf8_bytes_populates_error_without_raising(self, tmp_path: Path) -> None:
        config_path = tmp_path / "cfg" / "secure-home.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_bytes(b"\xff\xfe\x00\x01not utf-8")
        config_path.chmod(0o600)
        run = _FakeRunner()

        report = secure_home_cli.collect(config_path=config_path, platform="darwin", run=run, ismount=lambda p: True)
        assert report.configured is False
        assert report.config_error is not None

    def test_non_darwin_skips_probes(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_UUID)
        _write_config(config_path, config)

        report = secure_home_cli.collect(
            config_path=config_path, platform="linux", run=_unused_runner, ismount=_unused_ismount
        )
        assert report.platform_supported is False
        assert report.configured is True
        assert report.filevault == "unknown"
        assert report.mounted is None
        assert report.verified is None
        assert report.mount_point == str(mount_point)
        assert report.volume_uuid == _UUID

    def test_status_as_json_round_trip(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point = _make_mount(tmp_path)
        home = mount_point / "hermes-home"
        home.mkdir()
        home.chmod(0o700)
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_UUID)
        _write_config(config_path, config)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.status(
            config_path=config_path, platform="darwin", run=run, ismount=lambda p: p == str(mount_point), as_json=True
        )
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["configured"] is True
        assert payload["verified"] is True
        assert payload["mount_point"] == str(mount_point)


# -----------------------------------------------------------------------------
# adopt
# -----------------------------------------------------------------------------
class TestAdopt:
    def test_happy_path(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.adopt(
            mount_point,
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
        )
        assert rc == 0

        loaded = load_config(config_path)
        assert loaded is not None
        assert loaded.volume_uuid == _UUID
        assert loaded.mount_point == mount_point

        home = mount_point / "hermes-home"
        assert home.is_dir()
        assert stat.S_IMODE(home.stat().st_mode) == 0o700

    def test_mountpoint_not_mounted(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=_unused_runner, ismount=lambda p: False
        )
        assert rc == 1
        assert not config_path.exists()
        assert not (mount_point / "hermes-home").exists()
        err = capsys.readouterr().err
        assert "secure-home adopt never mounts a volume" in err

    def test_boot_volume(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(
            diskutil_result=_diskutil_result(_good_plist(mount_point, reported_mount_point="/System/Volumes/Data"))
        )
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert not config_path.exists()
        assert not (mount_point / "hermes-home").exists()
        err = capsys.readouterr().err
        assert "FileVault" in err

    def test_ownership_disabled(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point, ownership=False)))
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert not config_path.exists()
        err = capsys.readouterr().err
        assert "-owners on" in err

    def test_ownership_absent_is_disabled(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point, ownership=None)))
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert not config_path.exists()

    def test_not_apfs(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point, filesystem="hfs")))
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert not config_path.exists()

    def test_not_encrypted_proper_false_and_no_matching_image(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(
            diskutil_result=_diskutil_result(_good_plist(mount_point, proper=False)),
            hdiutil_result=_hdiutil_result([]),
        )
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert not config_path.exists()
        assert any(call[0] == "hdiutil" for call in run.calls)

    def test_encrypted_via_backing_image(self, tmp_path: Path) -> None:
        """Exercises the ``hdiutil`` dispatch: ``EncryptionThisVolumeProper`` absent,
        but a matching backing disk image reports ``image-encrypted`` true."""
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(
            diskutil_result=_diskutil_result(_good_plist(mount_point, proper=None)),
            hdiutil_result=_hdiutil_result([_hdiutil_image(["/dev/disk3s2"], encrypted=True)]),
        )
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 0
        assert any(call[0] == "hdiutil" for call in run.calls)
        loaded = load_config(config_path)
        assert loaded is not None
        assert loaded.volume_uuid == _UUID

    def test_missing_volume_uuid(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point, uuid=None)))
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert not config_path.exists()
        err = capsys.readouterr().err
        assert "VolumeUUID" in err

    def test_existing_config_without_force_refuses_and_leaves_it_unchanged(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        other_mount = _make_mount(tmp_path, name="other")
        config_path = tmp_path / "cfg" / "secure-home.json"
        original = SecureHomeConfig(version=1, mount_point=other_mount, volume_uuid=_OTHER_UUID)
        _write_config(config_path, original)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert load_config(config_path) == original

    def test_existing_config_with_force_is_replaced(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        other_mount = _make_mount(tmp_path, name="other")
        config_path = tmp_path / "cfg" / "secure-home.json"
        original = SecureHomeConfig(version=1, mount_point=other_mount, volume_uuid=_OTHER_UUID)
        _write_config(config_path, original)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True, force=True
        )
        assert rc == 0
        replaced = load_config(config_path)
        assert replaced is not None
        assert replaced.mount_point == mount_point
        assert replaced.volume_uuid == _UUID

    def test_corrupt_config_without_force_refuses(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("not json", encoding="utf-8")
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 1
        assert config_path.read_text(encoding="utf-8") == "not json"

    def test_corrupt_config_with_force_is_replaced(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        config_path = tmp_path / "cfg" / "secure-home.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("not json", encoding="utf-8")
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True, force=True
        )
        assert rc == 0
        replaced = load_config(config_path)
        assert replaced is not None
        assert replaced.volume_uuid == _UUID

    def test_non_darwin_refuses(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        config_path = tmp_path / "cfg" / "secure-home.json"
        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="linux", run=_unused_runner, ismount=_unused_ismount
        )
        assert rc == 1
        assert not config_path.exists()

    def test_existing_home_dir_is_left_alone(self, tmp_path: Path) -> None:
        mount_point = _make_mount(tmp_path)
        home = mount_point / "hermes-home"
        home.mkdir()
        home.chmod(0o700)
        marker = home / "marker.txt"
        marker.write_text("keep me", encoding="utf-8")
        config_path = tmp_path / "cfg" / "secure-home.json"
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.adopt(
            mount_point, config_path=config_path, platform="darwin", run=run, ismount=lambda p: True
        )
        assert rc == 0
        assert marker.read_text(encoding="utf-8") == "keep me"

    def test_rollback_on_late_save_config_failure(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``--force`` with the config's PARENT directory symlinked: every
        identity check and the home-dir creation succeed, but ``save_config``
        refuses late (a symlinked parent). The ``hermes-home`` directory
        ``adopt`` created must be rolled back (``rmdir``), the refusal must
        reach stderr as a clean message (no traceback), and rc must be 1.
        """
        mount_point = _make_mount(tmp_path)
        real_cfg_dir = tmp_path / "real_cfg"
        real_cfg_dir.mkdir()
        link_cfg_dir = tmp_path / "link_cfg"
        link_cfg_dir.symlink_to(real_cfg_dir)
        config_path = link_cfg_dir / "secure-home.json"
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))

        rc = secure_home_cli.adopt(
            mount_point,
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
            force=True,
        )
        assert rc == 1
        assert not (mount_point / "hermes-home").exists()
        err = capsys.readouterr().err
        assert "symlink" in err
        assert "Traceback" not in err


# -----------------------------------------------------------------------------
# run
# -----------------------------------------------------------------------------
class TestRun:
    def _configured(self, tmp_path: Path) -> tuple[Path, Path]:
        mount_point = _make_mount(tmp_path)
        home = mount_point / "hermes-home"
        home.mkdir()
        home.chmod(0o700)
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_UUID)
        _write_config(config_path, config)
        return mount_point, config_path

    def _configured_without_home_dir(self, tmp_path: Path) -> tuple[Path, Path]:
        """Like ``_configured``, but never materialises ``hermes-home`` — for
        proving ``run_command`` never creates it on a locked/unmounted volume."""
        mount_point = tmp_path / "mnt"  # not even created: definitely "not mounted"
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_UUID)
        _write_config(config_path, config)
        return mount_point, config_path

    def test_happy_path(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))
        exec_fn = _FakeExec()
        environ = {"PATH": "/usr/bin", "FOO": "bar"}

        rc = secure_home_cli.run_command(
            ["hermes", "--version"],
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
            exec_fn=exec_fn,
            environ=environ,
            which=_fake_which(),
        )
        assert rc == 0
        assert exec_fn.captured is not None
        file, argv, env = exec_fn.captured
        assert file == "/resolved/hermes"
        assert argv == ["hermes", "--version"]
        assert env["HERMES_HOME"] == str(mount_point / "hermes-home")
        assert env["FOO"] == "bar"
        assert env["PATH"] == "/usr/bin"

    def test_leading_separator_is_stripped(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))
        exec_fn = _FakeExec()

        rc = secure_home_cli.run_command(
            ["--", "hermes", "--version"],
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
            exec_fn=exec_fn,
            environ={},
            which=_fake_which(),
        )
        assert rc == 0
        assert exec_fn.captured is not None
        _, argv, _ = exec_fn.captured
        assert argv == ["hermes", "--version"]

    def test_empty_command_after_stripping(self, tmp_path: Path) -> None:
        _, config_path = self._configured(tmp_path)
        rc = secure_home_cli.run_command(
            ["--"], config_path=config_path, platform="darwin", run=_unused_runner, ismount=_unused_ismount
        )
        assert rc == 2

    def test_not_configured(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        config_path = tmp_path / "cfg" / "secure-home.json"
        rc = secure_home_cli.run_command(
            ["hermes"], config_path=config_path, platform="darwin", run=_unused_runner, ismount=_unused_ismount
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "Secure home is not configured. Run 'hermes-mordred secure-home adopt <mountpoint>' first." in err

    def test_corrupt_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        config_path = tmp_path / "cfg" / "secure-home.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("not json", encoding="utf-8")
        config_path.chmod(0o600)
        rc = secure_home_cli.run_command(
            ["hermes"], config_path=config_path, platform="darwin", run=_unused_runner, ismount=_unused_ismount
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "JSON" in err

    def test_locked(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point, config_path = self._configured_without_home_dir(tmp_path)
        run = _FakeRunner()
        rc = secure_home_cli.run_command(
            ["hermes"], config_path=config_path, platform="darwin", run=run, ismount=lambda p: False
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "Secure Hermes home is locked. Unlock it to continue." in err
        assert not (mount_point / "hermes-home").exists()

    def test_uuid_mismatch(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point, config_path = self._configured(tmp_path)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point, uuid=_OTHER_UUID)))
        rc = secure_home_cli.run_command(
            ["hermes"], config_path=config_path, platform="darwin", run=run, ismount=lambda p: p == str(mount_point)
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "A different volume is mounted at the configured path." in err

    @pytest.mark.parametrize("var_name", ["MORDRED_SEKEY_STORE", "MORDRED_TPMKEY_STORE", "HERMES_SAFE_MODE"])
    def test_poisoned_env_var_refuses(self, tmp_path: Path, var_name: str, capsys: pytest.CaptureFixture[str]) -> None:
        _, config_path = self._configured(tmp_path)
        rc = secure_home_cli.run_command(
            ["hermes"],
            config_path=config_path,
            platform="darwin",
            run=_unused_runner,
            ismount=_unused_ismount,
            environ={var_name: "/somewhere/else"},
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "refusing to launch" in err
        assert var_name in err

    def test_poisoned_env_var_empty_string_proceeds(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))
        exec_fn = _FakeExec()
        rc = secure_home_cli.run_command(
            ["hermes"],
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
            exec_fn=exec_fn,
            environ={"MORDRED_SEKEY_STORE": ""},
            which=_fake_which(),
        )
        assert rc == 0
        assert exec_fn.captured is not None

    def test_which_returns_none_is_command_not_found(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))
        rc = secure_home_cli.run_command(
            ["nonexistent-binary"],
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
            exec_fn=_FakeExec(),
            environ={},
            which=_which_none,
        )
        assert rc == 127

    def test_exec_file_not_found_is_127(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))
        exec_fn = _FakeExec(raise_not_found=True)
        rc = secure_home_cli.run_command(
            ["nonexistent-binary"],
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
            exec_fn=exec_fn,
            environ={},
            which=_fake_which(),
        )
        assert rc == 127

    def test_exec_permission_error_is_126(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path)
        run = _FakeRunner(diskutil_result=_diskutil_result(_good_plist(mount_point)))
        exec_fn = _FakeExec(raise_permission=True)
        rc = secure_home_cli.run_command(
            ["not-executable"],
            config_path=config_path,
            platform="darwin",
            run=run,
            ismount=lambda p: p == str(mount_point),
            exec_fn=exec_fn,
            environ={},
            which=_fake_which(),
        )
        assert rc == 126

    def test_non_darwin_refuses(self, tmp_path: Path) -> None:
        _, config_path = self._configured(tmp_path)
        rc = secure_home_cli.run_command(
            ["hermes"],
            config_path=config_path,
            platform="linux",
            run=_unused_runner,
            ismount=_unused_ismount,
            exec_fn=_FakeExec(),
            environ={},
        )
        assert rc == 1

    def test_never_creates_at_unmounted_mountpoint(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured_without_home_dir(tmp_path)
        run = _FakeRunner()
        rc = secure_home_cli.run_command(
            ["hermes"], config_path=config_path, platform="darwin", run=run, ismount=lambda p: False
        )
        assert rc == 1
        assert not (mount_point / "hermes-home").exists()


# -----------------------------------------------------------------------------
# argparse delegation wiring
# -----------------------------------------------------------------------------
class TestParserDelegation:
    """``_secure_home_parsers._handle_secure_home_*`` -> ``secure_home_cli.cli_*``.

    Each handler lazy-imports ``secure_home_cli`` and calls the matching
    ``cli_*`` unqualified attribute, so monkeypatching that attribute on the
    already-imported module intercepts the call.
    """

    def test_handle_status_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, argparse.Namespace] = {}

        def fake_cli_status(args: argparse.Namespace) -> int:
            captured["args"] = args
            return 7

        monkeypatch.setattr(secure_home_cli, "cli_status", fake_cli_status)
        ns = argparse.Namespace(json=True)
        assert _secure_home_parsers._handle_secure_home_status(ns) == 7
        assert captured["args"] is ns

    def test_handle_adopt_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, argparse.Namespace] = {}

        def fake_cli_adopt(args: argparse.Namespace) -> int:
            captured["args"] = args
            return 7

        monkeypatch.setattr(secure_home_cli, "cli_adopt", fake_cli_adopt)
        ns = argparse.Namespace(mountpoint="/Volumes/x", force=True)
        assert _secure_home_parsers._handle_secure_home_adopt(ns) == 7
        assert captured["args"] is ns

    def test_handle_run_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, argparse.Namespace] = {}

        def fake_cli_run(args: argparse.Namespace) -> int:
            captured["args"] = args
            return 7

        monkeypatch.setattr(secure_home_cli, "cli_run", fake_cli_run)
        ns = argparse.Namespace(command=["--", "hermes"])
        assert _secure_home_parsers._handle_secure_home_run(ns) == 7
        assert captured["args"] is ns


class TestCliDefaultsResolution:
    """``secure_home_cli.cli_*`` -> the public ``status``/``adopt``/``run_command`` API.

    Each ``cli_*`` calls the bare module-level name, resolved from the
    module's globals at call time — monkeypatching that attribute on the
    module intercepts it the same way the parser-delegation tests do above.
    """

    def test_cli_status_maps_namespace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_status(**kwargs: object) -> int:
            captured.update(kwargs)
            return 7

        config_path = tmp_path / "cfg.json"
        monkeypatch.setattr(secure_home_cli, "status", fake_status)
        monkeypatch.setattr(secure_home_cli, "resolve_config_path", lambda: config_path)

        rc = secure_home_cli.cli_status(argparse.Namespace(json=True))
        assert rc == 7
        assert captured["config_path"] == config_path
        assert captured["platform"] == sys.platform
        assert captured["as_json"] is True

    def test_cli_status_json_defaults_false_when_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_status(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(secure_home_cli, "status", fake_status)
        monkeypatch.setattr(secure_home_cli, "resolve_config_path", lambda: tmp_path / "cfg.json")

        secure_home_cli.cli_status(argparse.Namespace())
        assert captured["as_json"] is False

    def test_cli_adopt_maps_namespace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_adopt(mount_point: Path, **kwargs: object) -> int:
            captured["mount_point"] = mount_point
            captured.update(kwargs)
            return 7

        config_path = tmp_path / "cfg.json"
        mountpoint = tmp_path / "mnt"
        monkeypatch.setattr(secure_home_cli, "adopt", fake_adopt)
        monkeypatch.setattr(secure_home_cli, "resolve_config_path", lambda: config_path)

        rc = secure_home_cli.cli_adopt(argparse.Namespace(mountpoint=str(mountpoint), force=True))
        assert rc == 7
        assert captured["mount_point"] == mountpoint
        assert captured["config_path"] == config_path
        assert captured["platform"] == sys.platform
        assert captured["force"] is True

    def test_cli_run_maps_namespace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_run_command(command: Sequence[str], **kwargs: object) -> int:
            captured["command"] = command
            captured.update(kwargs)
            return 7

        config_path = tmp_path / "cfg.json"
        monkeypatch.setattr(secure_home_cli, "run_command", fake_run_command)
        monkeypatch.setattr(secure_home_cli, "resolve_config_path", lambda: config_path)

        rc = secure_home_cli.cli_run(argparse.Namespace(command=["--", "hermes"]))
        assert rc == 7
        assert captured["command"] == ["--", "hermes"]
        assert captured["config_path"] == config_path
        assert captured["platform"] == sys.platform
