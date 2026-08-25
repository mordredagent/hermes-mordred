"""Tests for ``mordred_hermes.wizard._secure_home_volume``.

Every ``hdiutil``/``diskutil`` call is injected via a recording fake runner
that stores ``(argv, timeout, input)`` per call and returns a scripted
``CompletedProcess`` (or raises) — no real subprocess is ever invoked and no
real volume is ever mounted. The suite is organized around the module's one
non-negotiable security property: the passphrase reaches the tools ONLY via
stdin (``input=``) — never in ``argv``, never in a raised exception or log
message. Covers:

- the default runner: pinned env, ``capture_output``/``text``/``check=False``,
  ``input=`` when given vs. ``stdin=DEVNULL`` when not.
- every function's exact ``argv`` shape and timeout.
- passphrase framing: exact bytes for ``hdiutil -stdinpass`` (no trailing
  newline), passphrase + exactly one ``DISKUTIL_STDIN_TERMINATOR`` for
  ``diskutil -stdinpassphrase``.
- every non-zero-exit error-code mapping, including busy detection and the
  wrong-passphrase hint.
- runner-level ``OSError``/``TimeoutExpired`` mapping to ``TOOL_FAILED``.
- ``attach_image``'s plist parsing (matched mount-point, fallback, no match,
  unparsable, malformed shapes).
- every input-validation ``ValueError``, raised before any subprocess call.
- the passphrase never appearing in ``str()`` of any raised exception.
"""

from __future__ import annotations

import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard import _secure_home_volume as _volume_module
from mordred_hermes.wizard._secure_home_probe import _PINNED_ENV
from mordred_hermes.wizard._secure_home_volume import (
    ATTACH_FAILED,
    CREATE_FAILED,
    DEFAULT_VOLUME_RUNNER,
    DETACH_FAILED,
    DISKUTIL_STDIN_TERMINATOR,
    LOCK_FAILED,
    TOOL_FAILED,
    UNLOCK_FAILED,
    VOLUME_BUSY,
    AttachResult,
    SecureHomeVolumeError,
    attach_image,
    create_encrypted_image,
    detach,
    force_unmount_native,
    lock_native_volume,
    unlock_native_volume,
)

_UUID = "1956CE7B-0F1B-4CE6-A9E4-BAAAD5CF9E1C"
_PASSPHRASE = "correct horse battery staple"  # test fixture, not a real secret


# -----------------------------------------------------------------------------
# Fake runner
# -----------------------------------------------------------------------------
class _RecordingRunner:
    """Records every call's ``(argv, timeout, input)`` and returns a scripted result or raises."""

    def __init__(
        self,
        *,
        result: subprocess.CompletedProcess[str] | None = None,
        exc: Exception | None = None,
    ) -> None:
        self._result = result
        self._exc = exc
        self.calls: list[tuple[tuple[str, ...], float, str | None]] = []

    def __call__(
        self, argv: Sequence[str], *, timeout: float, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((tuple(argv), timeout, input))
        if self._exc is not None:
            raise self._exc
        assert self._result is not None
        if tuple(argv[:2]) == ("hdiutil", "create") and self._result.returncode == 0:
            # `create_encrypted_image` chmods the image it just made, so a fake
            # that returns success without a file on disk is not a faithful
            # stand-in — it would make every create test fail on ENOENT.
            Path(argv[-1]).write_bytes(b"fake sparseimage")
        return self._result


def _unused_runner(
    argv: Sequence[str], *, timeout: float, input: str | None = None
) -> subprocess.CompletedProcess[str]:
    raise AssertionError(f"subprocess should not have been invoked: {argv}")


def _completed(
    argv: Sequence[str], *, returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=list(argv), returncode=returncode, stdout=stdout, stderr=stderr)


class _ChmodSpy:
    """Stands in for the module's ``os``, recording (or failing) ``chmod`` only.

    Every other attribute delegates to the real module, so nothing else in
    ``_secure_home_volume`` notices the substitution.
    """

    def __init__(self, recorded: list[tuple[str, int]], *, real: Any, error: Exception | None = None) -> None:
        self._recorded = recorded
        self._real = real
        self._error = error

    def chmod(self, path: Any, mode: int) -> None:
        if self._error is not None:
            raise self._error
        self._recorded.append((str(path), mode))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


# -----------------------------------------------------------------------------
# _default_volume_runner
# -----------------------------------------------------------------------------
class TestDefaultVolumeRunner:
    def test_pins_env_and_flags_with_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _completed(argv)

        monkeypatch.setattr(subprocess, "run", fake_run)
        DEFAULT_VOLUME_RUNNER(("hdiutil", "create"), timeout=12.0, input="secret")
        assert captured["argv"] == ["hdiutil", "create"]
        kwargs = captured["kwargs"]
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["check"] is False
        assert kwargs["timeout"] == 12.0
        assert kwargs["env"] == _PINNED_ENV
        assert kwargs["input"] == "secret"
        assert "stdin" not in kwargs

    def test_no_input_uses_devnull_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["kwargs"] = kwargs
            return _completed(argv)

        monkeypatch.setattr(subprocess, "run", fake_run)
        DEFAULT_VOLUME_RUNNER(("diskutil", "apfs", "lockVolume", _UUID), timeout=5.0)
        kwargs = captured["kwargs"]
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert "input" not in kwargs
        assert kwargs["env"] == _PINNED_ENV


# -----------------------------------------------------------------------------
# create_encrypted_image
# -----------------------------------------------------------------------------
class TestPassphraseEncodingAndFraming:
    """HIGH-2: the passphrase's bytes on the wire must not depend on the caller's locale."""

    @pytest.mark.parametrize("with_input", [True, False])
    def test_default_runner_pins_utf8_strict_on_both_branches(
        self, monkeypatch: pytest.MonkeyPatch, with_input: bool
    ) -> None:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured.update(kwargs)
            return _completed(argv)

        monkeypatch.setattr(subprocess, "run", fake_run)
        DEFAULT_VOLUME_RUNNER(("hdiutil", "info"), timeout=1.0, input=_PASSPHRASE if with_input else None)
        assert captured["encoding"] == "utf-8"
        assert captured["errors"] == "strict"

    def test_unencodable_passphrase_is_tool_failed_without_leaking_it(self, tmp_path: Path) -> None:
        """A lone surrogate cannot be UTF-8 encoded; the refusal must quote
        neither the character nor its offset (``UnicodeEncodeError.__str__``
        does both)."""
        surrogate = "pass\ud800word"

        def encoding_runner(
            argv: Sequence[str], *, timeout: float, input: str | None = None
        ) -> subprocess.CompletedProcess[str]:
            assert input is not None
            input.encode("utf-8")  # raises UnicodeEncodeError, like subprocess would
            raise AssertionError("unreachable")

        with pytest.raises(SecureHomeVolumeError) as exc_info:
            attach_image(tmp_path / "i.sparseimage", tmp_path / "m", passphrase=surrogate, run=encoding_runner)
        assert exc_info.value.code == TOOL_FAILED
        message = str(exc_info.value)
        assert "cannot be encoded as UTF-8" in message
        assert "\ud800" not in message
        assert "position" not in message
        assert "surrogate" not in message

    def test_undecodable_tool_output_is_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=UnicodeDecodeError("utf-8", b"\xff\xfe", 0, 1, "invalid start byte"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            detach(tmp_path / "m", run=run)
        assert exc_info.value.code == TOOL_FAILED
        assert "not valid UTF-8" in str(exc_info.value)

    @pytest.mark.parametrize("bad", ["pass\nword", "pass\x00word"])
    def test_newline_and_nul_passphrases_are_refused_before_any_tool_call(self, tmp_path: Path, bad: str) -> None:
        """Both tools read a *terminated* passphrase, so an embedded terminator
        would create a volume that only a truncated prefix can reopen."""
        for call in (
            lambda: create_encrypted_image(
                tmp_path / "i.sparseimage", size="1g", volume_name="V", passphrase=bad, run=_unused_runner
            ),
            lambda: attach_image(tmp_path / "i.sparseimage", tmp_path / "m", passphrase=bad, run=_unused_runner),
            lambda: unlock_native_volume(_UUID, tmp_path / "m", passphrase=bad, run=_unused_runner),
        ):
            with pytest.raises(ValueError) as exc_info:
                call()
            assert bad not in str(exc_info.value)

    def test_size_regex_rejects_a_trailing_newline(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            create_encrypted_image(
                tmp_path / "i.sparseimage", size="4g\n", volume_name="V", passphrase=_PASSPHRASE, run=_unused_runner
            )


class TestImagePermissions:
    """MEDIUM-2: a fresh image is a copyable ciphertext blob; 0600 is its only local gate."""

    def test_successful_create_restricts_the_image_to_0600(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chmods: list[tuple[str, int]] = []
        monkeypatch.setattr(_volume_module, "os", _ChmodSpy(chmods, real=_volume_module.os), raising=True)
        image = tmp_path / "img.sparseimage"
        create_encrypted_image(
            image, size="1g", volume_name="V", passphrase=_PASSPHRASE, run=_RecordingRunner(result=_completed(("h",)))
        )
        assert chmods == [(str(image), 0o600)]

    def test_real_create_leaves_the_image_at_0600(self, tmp_path: Path) -> None:
        image = tmp_path / "img.sparseimage"
        create_encrypted_image(
            image, size="1g", volume_name="V", passphrase=_PASSPHRASE, run=_RecordingRunner(result=_completed(("h",)))
        )
        assert stat.S_IMODE(image.stat().st_mode) == 0o600

    def test_no_chmod_when_create_failed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chmods: list[tuple[str, int]] = []
        monkeypatch.setattr(_volume_module, "os", _ChmodSpy(chmods, real=_volume_module.os), raising=True)
        with pytest.raises(SecureHomeVolumeError):
            create_encrypted_image(
                tmp_path / "img.sparseimage",
                size="1g",
                volume_name="V",
                passphrase=_PASSPHRASE,
                run=_RecordingRunner(result=_completed(("h",), returncode=1, stderr="nope")),
            )
        assert chmods == []

    def test_chmod_failure_is_create_failed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        spy = _ChmodSpy([], real=_volume_module.os, error=PermissionError("read-only"))
        monkeypatch.setattr(_volume_module, "os", spy, raising=True)
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            create_encrypted_image(
                tmp_path / "img.sparseimage",
                size="1g",
                volume_name="V",
                passphrase=_PASSPHRASE,
                run=_RecordingRunner(result=_completed(("h",))),
            )
        assert exc_info.value.code == CREATE_FAILED
        assert "0600" in str(exc_info.value)
        assert _PASSPHRASE not in str(exc_info.value)


class TestMountPointValidation:
    """LOW-2: "validates every non-secret input" must be true of the paths too."""

    def test_relative_paths_are_refused_before_any_tool_call(self, tmp_path: Path) -> None:
        relative = Path("relative/mnt")
        for call in (
            lambda: attach_image(tmp_path / "i.sparseimage", relative, passphrase=_PASSPHRASE, run=_unused_runner),
            lambda: detach(relative, run=_unused_runner),
            lambda: unlock_native_volume(_UUID, relative, passphrase=_PASSPHRASE, run=_unused_runner),
            lambda: force_unmount_native(relative, run=_unused_runner),
        ):
            with pytest.raises(ValueError, match="absolute"):
                call()

    def test_detach_accepts_a_device_node(self) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        detach(Path("/dev/disk9"), run=run)
        assert run.calls[0][0] == ("hdiutil", "detach", "/dev/disk9")


class TestCreateEncryptedImage:
    def test_argv_and_timeout_and_input(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        image_path = tmp_path / "secure-home.sparseimage"
        create_encrypted_image(image_path, size="10g", volume_name="SecureHermes", passphrase=_PASSPHRASE, run=run)
        assert len(run.calls) == 1
        argv, timeout, sent_input = run.calls[0]
        assert argv == (
            "hdiutil",
            "create",
            "-size",
            "10g",
            "-type",
            "SPARSE",
            "-fs",
            "APFS",
            "-encryption",
            "AES-256",
            "-stdinpass",
            "-volname",
            "SecureHermes",
            str(image_path),
        )
        assert timeout == 300.0
        assert sent_input == _PASSPHRASE
        assert not sent_input.endswith("\n")

    def test_passphrase_never_in_argv(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        create_encrypted_image(
            tmp_path / "img.sparseimage", size="1g", volume_name="V", passphrase=_PASSPHRASE, run=run
        )
        argv, _timeout, _input = run.calls[0]
        assert _PASSPHRASE not in argv
        assert all(_PASSPHRASE not in part for part in argv)

    def test_nonzero_exit_raises_create_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="disk full"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            create_encrypted_image(
                tmp_path / "img.sparseimage", size="1g", volume_name="V", passphrase=_PASSPHRASE, run=run
            )
        assert exc_info.value.code == CREATE_FAILED
        assert "disk full" in str(exc_info.value)
        assert "hdiutil create" in str(exc_info.value)
        assert _PASSPHRASE not in str(exc_info.value)

    def test_oserror_raises_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=OSError("hdiutil not found"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            create_encrypted_image(
                tmp_path / "img.sparseimage", size="1g", volume_name="V", passphrase=_PASSPHRASE, run=run
            )
        assert exc_info.value.code == TOOL_FAILED
        assert _PASSPHRASE not in str(exc_info.value)

    def test_timeout_expired_raises_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=subprocess.TimeoutExpired(cmd="hdiutil", timeout=300.0))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            create_encrypted_image(
                tmp_path / "img.sparseimage", size="1g", volume_name="V", passphrase=_PASSPHRASE, run=run
            )
        assert exc_info.value.code == TOOL_FAILED

    def test_relative_image_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="absolute"):
            create_encrypted_image(
                Path("relative.sparseimage"), size="1g", volume_name="V", passphrase=_PASSPHRASE, run=_unused_runner
            )

    @pytest.mark.parametrize("size", ["", "abc", "10x", "-5g", "10 g", "10G!"])
    def test_invalid_size_rejected(self, tmp_path: Path, size: str) -> None:
        with pytest.raises(ValueError):
            create_encrypted_image(
                tmp_path / "img.sparseimage", size=size, volume_name="V", passphrase=_PASSPHRASE, run=_unused_runner
            )

    @pytest.mark.parametrize("size", ["10g", "10G", "512", "1t", "1T", "500m", "1b"])
    def test_valid_sizes_accepted(self, tmp_path: Path, size: str) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        create_encrypted_image(
            tmp_path / "img.sparseimage", size=size, volume_name="V", passphrase=_PASSPHRASE, run=run
        )
        assert run.calls[0][0][3] == size

    def test_empty_volume_name_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="empty"):
            create_encrypted_image(
                tmp_path / "img.sparseimage", size="1g", volume_name="", passphrase=_PASSPHRASE, run=_unused_runner
            )

    def test_overlong_volume_name_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="64"):
            create_encrypted_image(
                tmp_path / "img.sparseimage",
                size="1g",
                volume_name="V" * 65,
                passphrase=_PASSPHRASE,
                run=_unused_runner,
            )

    def test_volume_name_at_max_length_accepted(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        create_encrypted_image(
            tmp_path / "img.sparseimage", size="1g", volume_name="V" * 64, passphrase=_PASSPHRASE, run=run
        )
        assert len(run.calls) == 1

    def test_volume_name_control_char_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="control"):
            create_encrypted_image(
                tmp_path / "img.sparseimage",
                size="1g",
                volume_name="Se\tcure",
                passphrase=_PASSPHRASE,
                run=_unused_runner,
            )

    def test_volume_name_slash_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="/"):
            create_encrypted_image(
                tmp_path / "img.sparseimage",
                size="1g",
                volume_name="Se/cure",
                passphrase=_PASSPHRASE,
                run=_unused_runner,
            )

    def test_volume_name_leading_dash_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="-"):
            create_encrypted_image(
                tmp_path / "img.sparseimage", size="1g", volume_name="-flag", passphrase=_PASSPHRASE, run=_unused_runner
            )

    def test_empty_passphrase_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="passphrase"):
            create_encrypted_image(
                tmp_path / "img.sparseimage", size="1g", volume_name="V", passphrase="", run=_unused_runner
            )

    def test_validation_happens_before_any_subprocess_call(self, tmp_path: Path) -> None:
        # _unused_runner raises AssertionError if invoked; ValueError instead proves
        # validation ran first.
        with pytest.raises(ValueError):
            create_encrypted_image(
                Path("relative.sparseimage"), size="bad", volume_name="", passphrase="", run=_unused_runner
            )


# -----------------------------------------------------------------------------
# attach_image
# -----------------------------------------------------------------------------
class TestAttachImage:
    def test_argv_and_timeout_and_input(self, tmp_path: Path) -> None:
        image_path = tmp_path / "secure-home.sparseimage"
        mount_point = tmp_path / "Volumes" / "SecureHermes"
        run = _RecordingRunner(result=_completed(("hdiutil",), stdout=""))
        attach_image(image_path, mount_point, passphrase=_PASSPHRASE, run=run)
        argv, timeout, sent_input = run.calls[0]
        assert argv == (
            "hdiutil",
            "attach",
            str(image_path),
            "-stdinpass",
            "-mountpoint",
            str(mount_point),
            "-nobrowse",
            "-owners",
            "on",
            "-plist",
        )
        assert timeout == 120.0
        assert sent_input == _PASSPHRASE
        assert not sent_input.endswith("\n")

    def test_passphrase_never_in_argv(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        argv, _timeout, _input = run.calls[0]
        assert all(_PASSPHRASE not in part for part in argv)

    def test_relative_image_path_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="absolute"):
            attach_image(Path("relative.sparseimage"), tmp_path / "mnt", passphrase=_PASSPHRASE, run=_unused_runner)

    def test_empty_passphrase_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="passphrase"):
            attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase="", run=_unused_runner)

    def test_nonzero_exit_raises_attach_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="I/O error"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert exc_info.value.code == ATTACH_FAILED
        assert "I/O error" in str(exc_info.value)
        assert _PASSPHRASE not in str(exc_info.value)

    def test_wrong_passphrase_hint_on_authentication_error(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="Authentication error"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert "wrong passphrase?" in str(exc_info.value)

    def test_wrong_passphrase_hint_on_passphrase_mention(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="invalid passphrase supplied"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert "wrong passphrase?" in str(exc_info.value)

    def test_no_wrong_passphrase_hint_on_unrelated_error(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="no space left on device"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert "wrong passphrase?" not in str(exc_info.value)

    def test_oserror_raises_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=OSError("hdiutil not found"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert exc_info.value.code == TOOL_FAILED

    def test_plist_device_node_matches_mount_point(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        plist = {
            "system-entities": [
                {"dev-entry": "/dev/disk9", "mount-point": ""},
                {"dev-entry": "/dev/disk9s1", "mount-point": str(mount_point)},
            ]
        }
        import plistlib

        run = _RecordingRunner(result=_completed(("hdiutil",), stdout=plistlib.dumps(plist).decode()))
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node="/dev/disk9s1", mount_point=mount_point)

    def test_plist_fallback_to_any_entity_with_mount_point(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        plist = {
            "system-entities": [
                {"dev-entry": "/dev/disk9", "mount-point": "/some/other/path"},
            ]
        }
        import plistlib

        run = _RecordingRunner(result=_completed(("hdiutil",), stdout=plistlib.dumps(plist).decode()))
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node="/dev/disk9", mount_point=mount_point)

    def test_plist_no_entity_with_mount_point_is_none(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        plist = {"system-entities": [{"dev-entry": "/dev/disk9"}]}
        import plistlib

        run = _RecordingRunner(result=_completed(("hdiutil",), stdout=plistlib.dumps(plist).decode()))
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node=None, mount_point=mount_point)

    def test_plist_unparsable_is_none(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(result=_completed(("hdiutil",), stdout="not a plist at all"))
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node=None, mount_point=mount_point)

    def test_plist_non_dict_is_none(self, tmp_path: Path) -> None:
        import plistlib

        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(result=_completed(("hdiutil",), stdout=plistlib.dumps(["a", "list"]).decode()))
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node=None, mount_point=mount_point)

    def test_plist_missing_system_entities_is_none(self, tmp_path: Path) -> None:
        import plistlib

        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(result=_completed(("hdiutil",), stdout=plistlib.dumps({}).decode()))
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node=None, mount_point=mount_point)

    def test_plist_system_entities_not_a_list_is_none(self, tmp_path: Path) -> None:
        import plistlib

        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(
            result=_completed(("hdiutil",), stdout=plistlib.dumps({"system-entities": "oops"}).decode())
        )
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node=None, mount_point=mount_point)

    def test_plist_non_dict_entities_are_skipped(self, tmp_path: Path) -> None:
        import plistlib

        mount_point = tmp_path / "mnt"
        plist = {"system-entities": ["not-a-dict", {"dev-entry": "/dev/disk9", "mount-point": str(mount_point)}]}
        run = _RecordingRunner(result=_completed(("hdiutil",), stdout=plistlib.dumps(plist).decode()))
        result = attach_image(tmp_path / "img.sparseimage", mount_point, passphrase=_PASSPHRASE, run=run)
        assert result == AttachResult(device_node="/dev/disk9", mount_point=mount_point)


# -----------------------------------------------------------------------------
# detach
# -----------------------------------------------------------------------------
class TestDetach:
    def test_argv_without_force(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        detach(mount_point, run=run)
        argv, timeout, sent_input = run.calls[0]
        assert argv == ("hdiutil", "detach", str(mount_point))
        assert timeout == 60.0
        assert sent_input is None

    def test_argv_with_force(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(result=_completed(("hdiutil",)))
        detach(mount_point, force=True, run=run)
        argv, _timeout, _input = run.calls[0]
        assert argv == ("hdiutil", "detach", str(mount_point), "-force")

    def test_nonzero_exit_without_busy_text_is_detach_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="unknown error"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            detach(tmp_path / "mnt", run=run)
        assert exc_info.value.code == DETACH_FAILED

    def test_busy_stderr_is_volume_busy(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="Resource busy"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            detach(tmp_path / "mnt", run=run)
        assert exc_info.value.code == VOLUME_BUSY

    def test_busy_case_insensitive(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="device is BUSY right now"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            detach(tmp_path / "mnt", run=run)
        assert exc_info.value.code == VOLUME_BUSY

    def test_busy_in_stdout(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stdout="resource busy", stderr=""))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            detach(tmp_path / "mnt", run=run)
        assert exc_info.value.code == VOLUME_BUSY

    def test_oserror_raises_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=OSError("hdiutil not found"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            detach(tmp_path / "mnt", run=run)
        assert exc_info.value.code == TOOL_FAILED

    def test_timeout_expired_raises_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=subprocess.TimeoutExpired(cmd="hdiutil", timeout=60.0))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            detach(tmp_path / "mnt", run=run)
        assert exc_info.value.code == TOOL_FAILED


# -----------------------------------------------------------------------------
# unlock_native_volume
# -----------------------------------------------------------------------------
class TestUnlockNativeVolume:
    def test_argv_and_timeout_and_input(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(result=_completed(("diskutil",)))
        unlock_native_volume(_UUID, mount_point, passphrase=_PASSPHRASE, run=run)
        argv, timeout, sent_input = run.calls[0]
        assert argv == ("diskutil", "apfs", "unlockVolume", _UUID, "-stdinpassphrase", "-mountpoint", str(mount_point))
        assert timeout == 120.0
        assert sent_input == _PASSPHRASE + DISKUTIL_STDIN_TERMINATOR

    def test_input_has_exactly_one_trailing_newline(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",)))
        unlock_native_volume(_UUID, tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        _argv, _timeout, sent_input = run.calls[0]
        assert sent_input is not None
        assert sent_input.endswith("\n")
        assert not sent_input.endswith("\n\n")
        assert sent_input[:-1] == _PASSPHRASE

    def test_diskutil_stdin_terminator_is_newline(self) -> None:
        assert DISKUTIL_STDIN_TERMINATOR == "\n"

    def test_passphrase_never_in_argv(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",)))
        unlock_native_volume(_UUID, tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        argv, _timeout, _input = run.calls[0]
        assert all(_PASSPHRASE not in part for part in argv)

    def test_invalid_uuid_rejected_before_subprocess_call(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="UUID"):
            unlock_native_volume("not-a-uuid", tmp_path / "mnt", passphrase=_PASSPHRASE, run=_unused_runner)

    def test_empty_passphrase_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="passphrase"):
            unlock_native_volume(_UUID, tmp_path / "mnt", passphrase="", run=_unused_runner)

    def test_nonzero_exit_raises_unlock_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",), returncode=1, stderr="unable to unlock"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            unlock_native_volume(_UUID, tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert exc_info.value.code == UNLOCK_FAILED
        assert _PASSPHRASE not in str(exc_info.value)

    def test_wrong_passphrase_hint(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",), returncode=1, stderr="Invalid passphrase"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            unlock_native_volume(_UUID, tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert "wrong passphrase?" in str(exc_info.value)

    def test_oserror_raises_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            unlock_native_volume(_UUID, tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
        assert exc_info.value.code == TOOL_FAILED
        assert _PASSPHRASE not in str(exc_info.value)


# -----------------------------------------------------------------------------
# lock_native_volume
# -----------------------------------------------------------------------------
class TestLockNativeVolume:
    def test_argv_and_timeout(self) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",)))
        lock_native_volume(_UUID, run=run)
        argv, timeout, sent_input = run.calls[0]
        assert argv == ("diskutil", "apfs", "lockVolume", _UUID)
        assert timeout == 60.0
        assert sent_input is None

    def test_invalid_uuid_rejected_before_subprocess_call(self) -> None:
        with pytest.raises(ValueError, match="UUID"):
            lock_native_volume("not-a-uuid", run=_unused_runner)

    def test_nonzero_exit_without_busy_is_lock_failed(self) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",), returncode=1, stderr="oops"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            lock_native_volume(_UUID, run=run)
        assert exc_info.value.code == LOCK_FAILED

    def test_busy_stderr_is_volume_busy(self) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",), returncode=1, stderr="Resource busy"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            lock_native_volume(_UUID, run=run)
        assert exc_info.value.code == VOLUME_BUSY

    def test_oserror_raises_tool_failed(self) -> None:
        run = _RecordingRunner(exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            lock_native_volume(_UUID, run=run)
        assert exc_info.value.code == TOOL_FAILED


# -----------------------------------------------------------------------------
# force_unmount_native
# -----------------------------------------------------------------------------
class TestForceUnmountNative:
    def test_argv_and_timeout(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        run = _RecordingRunner(result=_completed(("diskutil",)))
        force_unmount_native(mount_point, run=run)
        argv, timeout, sent_input = run.calls[0]
        assert argv == ("diskutil", "unmount", "force", str(mount_point))
        assert timeout == 60.0
        assert sent_input is None

    def test_nonzero_exit_raises_detach_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(result=_completed(("diskutil",), returncode=1, stderr="cannot unmount"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            force_unmount_native(tmp_path / "mnt", run=run)
        assert exc_info.value.code == DETACH_FAILED

    def test_oserror_raises_tool_failed(self, tmp_path: Path) -> None:
        run = _RecordingRunner(exc=OSError("diskutil not found"))
        with pytest.raises(SecureHomeVolumeError) as exc_info:
            force_unmount_native(tmp_path / "mnt", run=run)
        assert exc_info.value.code == TOOL_FAILED


# -----------------------------------------------------------------------------
# Cross-cutting: passphrase must never leak into any raised exception
# -----------------------------------------------------------------------------
class TestPassphraseNeverLeaks:
    def test_create_failure_paths(self, tmp_path: Path) -> None:
        # stderr/exc text deliberately does NOT contain the passphrase: real
        # hdiutil/diskutil never echo it back. This proves our own message
        # construction never re-introduces it (e.g. via a stray f-string).
        for run in (
            _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="disk full")),
            _RecordingRunner(exc=OSError("boom")),
        ):
            try:
                create_encrypted_image(
                    tmp_path / "img.sparseimage", size="1g", volume_name="V", passphrase=_PASSPHRASE, run=run
                )
            except SecureHomeVolumeError as exc:
                assert _PASSPHRASE not in str(exc)
            else:
                pytest.fail("expected SecureHomeVolumeError")

    def test_attach_failure_paths(self, tmp_path: Path) -> None:
        for run in (
            _RecordingRunner(result=_completed(("hdiutil",), returncode=1, stderr="nope")),
            _RecordingRunner(exc=OSError("boom")),
        ):
            try:
                attach_image(tmp_path / "img.sparseimage", tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
            except SecureHomeVolumeError as exc:
                assert _PASSPHRASE not in str(exc)
            else:
                pytest.fail("expected SecureHomeVolumeError")

    def test_unlock_failure_paths(self, tmp_path: Path) -> None:
        for run in (
            _RecordingRunner(result=_completed(("diskutil",), returncode=1, stderr="nope")),
            _RecordingRunner(exc=OSError("boom")),
        ):
            try:
                unlock_native_volume(_UUID, tmp_path / "mnt", passphrase=_PASSPHRASE, run=run)
            except SecureHomeVolumeError as exc:
                assert _PASSPHRASE not in str(exc)
            else:
                pytest.fail("expected SecureHomeVolumeError")
