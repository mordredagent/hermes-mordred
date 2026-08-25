"""Tests for ``mordred_hermes.wizard.secure_home_lifecycle_cli``.

Every ``hdiutil``/``diskutil`` invocation is injected (a recording
``FakeVolumeRunner`` for the mutating calls, a scripted ``FakeRunner`` for the
read-only identity chain), every prompt is a ``ScriptedPromptIO``, and the
mount state is a shared ``MountState`` that the fake attach/detach flips — so
no real volume is ever created, attached, or destroyed.

The suite is organised around the three properties Phase 2 must never lose:

* the passphrase reaches a tool ONLY through ``input=`` — never ``argv``,
  never stdout/stderr, never an exception message, and there is no flag or
  environment variable that could carry it;
* ``init`` never overwrites an existing image (``--force`` included) and
  never deletes anything it did not create in the same run — every failure
  after creation rolls back exactly this run's artifacts;
* ``mount`` re-verifies the full chain after attaching (and detaches again on
  failure), and ``unmount`` verifies volume identity *before* detaching so a
  foreign volume mounted at the configured path is refused.
"""

from __future__ import annotations

import argparse
import os
import plistlib
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard import _secure_home_parsers, secure_home_lifecycle_cli
from mordred_hermes.wizard._secure_home_paths import (
    BACKING_APFS_VOLUME,
    BACKING_DISK_IMAGE,
    CONFIG_VERSION,
    MODE_BALANCED,
    MODE_STRICT,
    Backing,
    SecureHomeConfig,
    load_config,
    save_config,
)

from ._secure_home_fakes import (
    FakeRunner,
    FakeVolumeRunner,
    MountState,
    ScriptedPromptIO,
    diskutil_result,
    good_plist,
    hdiutil_result,
    unused_ismount,
    unused_runner,
    unused_volume_runner,
)

_UUID = "ABCD1234-0000-0000-0000-000000000000"
_OTHER_UUID = "FFFFFFFF-0000-0000-0000-000000000000"
_PASSPHRASE = "correct horse battery staple"  # test fixture, not a real secret

_MODE_LABEL = "Secure-home mode"
_NEW_PASSPHRASE_LABEL = "Choose the secure-home volume passphrase"
_CONFIRM_LABEL = "Re-enter the passphrase"
_UNLOCK_LABEL = "Secure-home volume passphrase"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _init_prompt(
    passphrase: str = _PASSPHRASE, *, confirm: str | None = None, mode: str | None = None
) -> ScriptedPromptIO:
    return ScriptedPromptIO(
        passwords=[passphrase, confirm if confirm is not None else passphrase],
        choices={_MODE_LABEL: mode} if mode is not None else None,
    )


def _probe_runner(mount_point: Path, **overrides: Any) -> FakeRunner:
    return FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, **overrides)))


def _init_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    return tmp_path / "img" / "secure.sparseimage", tmp_path / "mnt", tmp_path / "cfg" / "secure-home.json"


def _run_init(
    tmp_path: Path,
    *,
    prompt_io: ScriptedPromptIO | None = None,
    volume_run: FakeVolumeRunner | None = None,
    run: FakeRunner | None = None,
    mount_state: MountState | None = None,
    **kwargs: Any,
) -> tuple[int, Path, Path, Path, FakeVolumeRunner]:
    """Drive ``init`` with the canonical happy-path wiring, overridable per test."""
    image, mount_point, config_path = _init_paths(tmp_path)
    state = mount_state if mount_state is not None else MountState()
    volume_runner = volume_run if volume_run is not None else FakeVolumeRunner(mount_state=state)
    rc = secure_home_lifecycle_cli.init(
        config_path=config_path,
        platform="darwin",
        prompt_io=prompt_io if prompt_io is not None else _init_prompt(),
        image_path=image,
        mount_point=mount_point,
        run=run if run is not None else _probe_runner(mount_point),
        volume_run=volume_runner,
        ismount=state.ismount,
        home_dir=tmp_path,
        **kwargs,
    )
    return rc, image, mount_point, config_path, volume_runner


def _write_config(config_path: Path, config: SecureHomeConfig) -> None:
    save_config(config, config_path)


def _image_config(mount_point: Path, image: Path) -> SecureHomeConfig:
    return SecureHomeConfig(
        version=CONFIG_VERSION,
        mount_point=mount_point,
        volume_uuid=_UUID,
        backing=Backing(BACKING_DISK_IMAGE, image),
        mode=MODE_BALANCED,
    )


def _native_config(mount_point: Path) -> SecureHomeConfig:
    return SecureHomeConfig(
        version=CONFIG_VERSION,
        mount_point=mount_point,
        volume_uuid=_UUID,
        backing=Backing(BACKING_APFS_VOLUME),
        mode=MODE_STRICT,
    )


def _v1_config(mount_point: Path) -> SecureHomeConfig:
    return SecureHomeConfig(version=1, mount_point=mount_point, volume_uuid=_UUID)


def _failed(action: str, *, stderr: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=action.split(), returncode=1, stdout="", stderr=stderr)


def _attach_plist_result(device_node: str, mount_point: str) -> subprocess.CompletedProcess[str]:
    """A successful ``hdiutil attach -plist`` naming the device node it brought up."""
    payload = {"system-entities": [{"dev-entry": device_node, "mount-point": mount_point}]}
    return subprocess.CompletedProcess(
        args=["hdiutil", "attach"], returncode=0, stdout=plistlib.dumps(payload).decode(), stderr=""
    )


def _attached_image_result(image: Path, device_node: str, mount_points: Sequence[str]) -> Any:
    """An ``hdiutil info -plist`` payload showing *image* attached at *mount_points*."""
    entities: list[dict[str, Any]] = [{"dev-entry": device_node}]
    entities += [{"dev-entry": f"{device_node}s{i + 1}", "mount-point": mp} for i, mp in enumerate(mount_points)]
    return hdiutil_result([{"image-path": str(image), "system-entities": entities}])


# -----------------------------------------------------------------------------
# default paths
# -----------------------------------------------------------------------------
class TestDefaultPaths:
    def test_default_image_path(self, tmp_path: Path) -> None:
        assert secure_home_lifecycle_cli.default_image_path(tmp_path) == (
            tmp_path / "Library" / "Application Support" / "hermes-mordred" / "secure-home.sparseimage"
        )

    def test_default_mount_point(self, tmp_path: Path) -> None:
        assert secure_home_lifecycle_cli.default_mount_point(tmp_path) == (
            tmp_path / "Library" / "Application Support" / "hermes-mordred" / "secure-home"
        )


# -----------------------------------------------------------------------------
# init
# -----------------------------------------------------------------------------
class TestInit:
    def test_happy_path_records_backing_and_mode(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc, image, mount_point, config_path, _volume_run = _run_init(tmp_path)
        assert rc == 0

        loaded = load_config(config_path)
        assert loaded is not None
        assert loaded.volume_uuid == _UUID
        assert loaded.mount_point == mount_point
        assert loaded.backing == Backing(BACKING_DISK_IMAGE, image)
        assert loaded.mode == MODE_BALANCED

        home = mount_point / "hermes-home"
        assert home.is_dir()
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
        assert stat.S_IMODE(mount_point.stat().st_mode) == 0o700

        captured = capsys.readouterr()
        assert "Secure home initialized." in captured.out
        assert f"  image       : {image}" in captured.out
        assert f"  mode        : {MODE_BALANCED}" in captured.out
        assert "NOT migrated" in captured.out

    def test_passphrase_only_reaches_stdin(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc, _image, _mount_point, _config_path, volume_run = _run_init(tmp_path)
        assert rc == 0
        create = next(call for call in volume_run.calls if call[0][:2] == ("hdiutil", "create"))
        attach = next(call for call in volume_run.calls if call[0][:2] == ("hdiutil", "attach"))
        for argv, _timeout, stdin_input in (create, attach):
            assert _PASSPHRASE not in " ".join(argv)
            assert stdin_input == _PASSPHRASE  # exactly, no trailing newline
        captured = capsys.readouterr()
        assert _PASSPHRASE not in captured.out
        assert _PASSPHRASE not in captured.err

    def test_argv_shapes(self, tmp_path: Path) -> None:
        rc, image, mount_point, _config_path, volume_run = _run_init(tmp_path, size="512m", volume_name="MyVol")
        assert rc == 0
        create = next(argv for argv, _, _ in volume_run.calls if argv[:2] == ("hdiutil", "create"))
        assert "-stdinpass" in create
        assert create[create.index("-size") + 1] == "512m"
        assert create[create.index("-volname") + 1] == "MyVol"
        assert create[-1] == str(image)
        attach = next(argv for argv, _, _ in volume_run.calls if argv[:2] == ("hdiutil", "attach"))
        assert attach[attach.index("-mountpoint") + 1] == str(mount_point)
        assert "-owners" in attach

    def test_default_paths_used_when_not_overridden(self, tmp_path: Path) -> None:
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        expected_mount = secure_home_lifecycle_cli.default_mount_point(tmp_path)
        rc = secure_home_lifecycle_cli.init(
            config_path=tmp_path / "cfg" / "secure-home.json",
            platform="darwin",
            prompt_io=_init_prompt(),
            run=_probe_runner(expected_mount),
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 0
        assert secure_home_lifecycle_cli.default_image_path(tmp_path).exists()
        assert (expected_mount / "hermes-home").is_dir()

    def test_non_darwin_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        image, mount_point, config_path = _init_paths(tmp_path)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="linux",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=mount_point,
            run=unused_runner,
            volume_run=unused_volume_runner,
            ismount=unused_ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert not config_path.exists()
        assert "macOS only" in capsys.readouterr().err

    def test_existing_config_refuses_without_force(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        image, mount_point, config_path = _init_paths(tmp_path)
        other = tmp_path / "other"
        other.mkdir()
        _write_config(config_path, _image_config(other, tmp_path / "other.sparseimage"))
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=mount_point,
            run=unused_runner,
            volume_run=unused_volume_runner,
            ismount=unused_ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert not image.exists()
        assert "--force" in capsys.readouterr().err

    def test_force_warns_that_the_previous_volume_is_left_untouched(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _image, _mount_point, config_path = _init_paths(tmp_path)
        other = tmp_path / "other"
        other.mkdir()
        _write_config(config_path, _image_config(other, tmp_path / "other.sparseimage"))
        rc, _image, _mp, _cfg, _vr = _run_init(tmp_path, force=True)
        assert rc == 0
        err = capsys.readouterr().err
        assert "left untouched" in err
        assert str(other) in err

    def test_existing_image_refuses_even_with_force(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        image, mount_point, config_path = _init_paths(tmp_path)
        image.parent.mkdir(parents=True)
        image.write_bytes(b"precious")
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=mount_point,
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
            force=True,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert image.read_bytes() == b"precious"
        assert volume_run.calls == []
        assert "never overwrites" in capsys.readouterr().err

    def test_existing_image_symlink_is_refused(self, tmp_path: Path) -> None:
        image, mount_point, config_path = _init_paths(tmp_path)
        image.parent.mkdir(parents=True)
        target = tmp_path / "elsewhere"
        target.write_bytes(b"x")
        image.symlink_to(target)
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=mount_point,
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert image.is_symlink()
        assert target.read_bytes() == b"x"
        assert volume_run.calls == []

    def test_non_empty_mount_point_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        image, mount_point, config_path = _init_paths(tmp_path)
        mount_point.mkdir()
        (mount_point / "stray").write_text("x", encoding="utf-8")
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=mount_point,
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert (mount_point / "stray").exists()
        assert "not empty" in capsys.readouterr().err

    def test_symlinked_mount_point_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        image, _mount_point, config_path = _init_paths(tmp_path)
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=link,
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert "symlink" in capsys.readouterr().err

    def test_already_mounted_mount_point_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        image, mount_point, config_path = _init_paths(tmp_path)
        mount_point.mkdir()
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=mount_point,
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert "already mounted" in capsys.readouterr().err

    def test_mount_point_that_is_a_file_refuses(self, tmp_path: Path) -> None:
        image, mount_point, config_path = _init_paths(tmp_path)
        mount_point.write_text("not a directory", encoding="utf-8")
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=image,
            mount_point=mount_point,
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert mount_point.read_text(encoding="utf-8") == "not a directory"

    def test_mode_flag_skips_the_prompt(self, tmp_path: Path) -> None:
        prompt_io = _init_prompt()
        rc, _image, _mp, config_path, _vr = _run_init(tmp_path, prompt_io=prompt_io, mode=MODE_STRICT)
        assert rc == 0
        assert prompt_io.choice_labels == []
        loaded = load_config(config_path)
        assert loaded is not None
        assert loaded.mode == MODE_STRICT

    def test_mode_from_the_prompt(self, tmp_path: Path) -> None:
        prompt_io = _init_prompt(mode=MODE_STRICT)
        rc, _image, _mp, config_path, _vr = _run_init(tmp_path, prompt_io=prompt_io)
        assert rc == 0
        assert prompt_io.choice_labels == [_MODE_LABEL]
        loaded = load_config(config_path)
        assert loaded is not None
        assert loaded.mode == MODE_STRICT

    def test_unknown_mode_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc, image, mount_point, config_path, volume_run = _run_init(tmp_path, mode="paranoid")
        assert rc == 1
        assert volume_run.calls == []
        assert not config_path.exists()
        assert not image.exists()
        assert not mount_point.exists()  # the directory this run created was rolled back
        assert "paranoid" in capsys.readouterr().err

    @pytest.mark.parametrize(
        ("prompt_io_factory", "expected"),
        [
            (lambda: ScriptedPromptIO(passwords=["", ""]), "must not be empty"),
            (lambda: ScriptedPromptIO(passwords=["short", "short"]), "at least"),
            (lambda: ScriptedPromptIO(passwords=[_PASSPHRASE, "different-one"]), "do not match"),
        ],
    )
    def test_passphrase_refusals_create_nothing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], prompt_io_factory: Any, expected: str
    ) -> None:
        rc, image, mount_point, config_path, volume_run = _run_init(tmp_path, prompt_io=prompt_io_factory())
        assert rc == 1
        assert volume_run.calls == []
        assert not image.exists()
        assert not config_path.exists()
        assert not mount_point.exists()
        assert expected in capsys.readouterr().err

    def test_create_failure_leaves_nothing_behind(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        state = MountState()
        volume_run = FakeVolumeRunner(
            mount_state=state, results={"hdiutil create": _failed("hdiutil create", stderr="no space left")}
        )
        rc, image, mount_point, config_path, _vr = _run_init(tmp_path, volume_run=volume_run, mount_state=state)
        assert rc == 1
        assert not image.exists()
        assert not config_path.exists()
        assert not mount_point.exists()
        assert volume_run.actions == ["hdiutil create"]
        assert "no space left" in capsys.readouterr().err

    def test_attach_failure_removes_the_image_this_run_created(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        state = MountState()
        volume_run = FakeVolumeRunner(
            mount_state=state,
            results={"hdiutil attach": _failed("hdiutil attach", stderr="Authentication error")},
        )
        rc, image, mount_point, config_path, _vr = _run_init(tmp_path, volume_run=volume_run, mount_state=state)
        assert rc == 1
        assert not image.exists()
        assert not config_path.exists()
        assert not mount_point.exists()
        assert "hdiutil detach" not in volume_run.actions  # nothing was attached
        assert "wrong passphrase?" in capsys.readouterr().err

    def test_verification_failure_detaches_and_rolls_back(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A ``noowners`` mount fails ``record_volume``'s chain after the attach succeeded."""
        _image, mount_point, _config_path = _init_paths(tmp_path)
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc, image, mount_point, config_path, _vr = _run_init(
            tmp_path, volume_run=volume_run, mount_state=state, run=run
        )
        assert rc == 1
        assert "hdiutil detach" in volume_run.actions
        assert not image.exists()
        assert not mount_point.exists()
        assert not config_path.exists()
        assert "-owners on" in capsys.readouterr().err

    def test_save_config_failure_rolls_everything_back(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        image = tmp_path / "img" / "secure.sparseimage"
        mount_point = tmp_path / "mnt"
        real_cfg = tmp_path / "real_cfg"
        real_cfg.mkdir()
        link_cfg = tmp_path / "link_cfg"
        link_cfg.symlink_to(real_cfg)
        config_path = link_cfg / "secure-home.json"
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)

        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=_init_prompt(),
            image_path=image,
            mount_point=mount_point,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
            force=True,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert "hdiutil detach" in volume_run.actions
        assert not image.exists()
        assert not mount_point.exists()
        assert not (real_cfg / "secure-home.json").exists()
        err = capsys.readouterr().err
        assert "symlink" in err
        assert "Traceback" not in err

    def test_rollback_detach_failure_tells_the_operator_what_to_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _image, mount_point, _config_path = _init_paths(tmp_path)
        state = MountState()
        volume_run = FakeVolumeRunner(
            mount_state=state,
            results={
                "hdiutil detach": _failed("hdiutil detach", stderr="Resource busy"),
            },
        )
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc, _image, _mp, _cfg, _vr = _run_init(tmp_path, volume_run=volume_run, mount_state=state, run=run)
        assert rc == 1
        err = capsys.readouterr().err
        assert "hdiutil detach" in err
        # A plain detach then a -force retry, both scripted to fail.
        assert volume_run.actions.count("hdiutil detach") == 2
        assert any("-force" in argv for argv, _, _ in volume_run.calls)

    def test_interrupt_at_the_passphrase_prompt_rolls_back_the_mount_dir(self, tmp_path: Path) -> None:
        """Ctrl-C after ``_prepare_mount_point`` created the directory: the
        exception still propagates (``cli.dispatch`` maps it to 130), but this
        run's artifacts must not survive it."""
        image, mount_point, config_path = _init_paths(tmp_path)
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        prompt_io = ScriptedPromptIO(password_raises=KeyboardInterrupt())

        with pytest.raises(KeyboardInterrupt):
            secure_home_lifecycle_cli.init(
                config_path=config_path,
                platform="darwin",
                prompt_io=prompt_io,
                image_path=image,
                mount_point=mount_point,
                run=_probe_runner(mount_point),
                volume_run=volume_run,
                ismount=state.ismount,
                home_dir=tmp_path,
            )
        assert prompt_io.password_labels == [_NEW_PASSPHRASE_LABEL]
        assert volume_run.calls == []
        assert not mount_point.exists()
        assert not image.exists()
        assert not config_path.exists()

    def test_interrupt_during_create_leaves_the_partial_image_with_a_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``hdiutil create`` is slow; a Ctrl-C mid-call can leave a partial image.

        Without a post-create identity there is no proof the file is ours, so
        the rollback leaves it and says so — deleting a concurrent run's
        image would be the far worse outcome.
        """
        state = MountState()
        volume_run = FakeVolumeRunner(
            mount_state=state,
            results={"hdiutil create": KeyboardInterrupt()},
            before={"hdiutil create": lambda argv: Path(argv[-1]).write_bytes(b"partial image")},
        )
        image, mount_point, config_path = _init_paths(tmp_path)

        with pytest.raises(KeyboardInterrupt):
            secure_home_lifecycle_cli.init(
                config_path=config_path,
                platform="darwin",
                prompt_io=_init_prompt(),
                image_path=image,
                mount_point=mount_point,
                run=_probe_runner(mount_point),
                volume_run=volume_run,
                ismount=state.ismount,
                home_dir=tmp_path,
            )
        assert image.read_bytes() == b"partial image"
        assert "interrupted before this run could confirm the file is its own" in capsys.readouterr().err
        assert not mount_point.exists()
        assert not config_path.exists()
        assert volume_run.actions == ["hdiutil create"]
        assert "could not detach" not in capsys.readouterr().err

    def test_interrupt_during_attach_removes_the_image_without_detaching(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An attach interrupted before the volume mounted must not trigger a
        detach it can only fail at (and warn about)."""
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state, results={"hdiutil attach": KeyboardInterrupt()})
        image, mount_point, config_path = _init_paths(tmp_path)

        with pytest.raises(KeyboardInterrupt):
            secure_home_lifecycle_cli.init(
                config_path=config_path,
                platform="darwin",
                prompt_io=_init_prompt(),
                image_path=image,
                mount_point=mount_point,
                run=_probe_runner(mount_point),
                volume_run=volume_run,
                ismount=state.ismount,
                home_dir=tmp_path,
            )
        assert volume_run.actions == ["hdiutil create", "hdiutil attach"]
        assert not image.exists()
        assert not mount_point.exists()
        assert "could not detach" not in capsys.readouterr().err

    def test_interrupt_after_a_successful_attach_detaches_again(self, tmp_path: Path) -> None:
        """The mirror case: the attach *did* mount, so rollback must detach."""
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        image, mount_point, config_path = _init_paths(tmp_path)
        run = FakeRunner(diskutil_exc=KeyboardInterrupt())

        with pytest.raises(KeyboardInterrupt):
            secure_home_lifecycle_cli.init(
                config_path=config_path,
                platform="darwin",
                prompt_io=_init_prompt(),
                image_path=image,
                mount_point=mount_point,
                run=run,
                volume_run=volume_run,
                ismount=state.ismount,
                home_dir=tmp_path,
            )
        assert volume_run.actions == ["hdiutil create", "hdiutil attach", "hdiutil detach"]
        assert not state.ismount(str(mount_point))
        assert not image.exists()
        assert not mount_point.exists()

    def test_rollback_never_unlinks_an_image_another_run_created(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """HIGH-1 PoC: the ``lexists`` reservation happens *before* the prompts.

        A concurrent ``init`` (modelled by a prompt-time hook) can win the path
        during that human-speed window; our ``hdiutil create`` then fails with
        "File exists" and rollback must leave the victim's file alone.
        """
        image, mount_point, config_path = _init_paths(tmp_path)
        victim = b"the other run's encrypted image"

        class _RacingPromptIO(ScriptedPromptIO):
            def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
                image.parent.mkdir(parents=True, exist_ok=True)
                image.write_bytes(victim)
                return super().ask_password(label, default, description=description)

        state = MountState()
        volume_run = FakeVolumeRunner(
            mount_state=state,
            create_files=False,
            results={"hdiutil create": _failed("hdiutil create", stderr="File exists")},
        )
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=_RacingPromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            image_path=image,
            mount_point=mount_point,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert image.read_bytes() == victim  # untouched
        assert volume_run.actions == []  # refused before hdiutil ran at all
        assert "already exists" in capsys.readouterr().err

    def test_rollback_leaves_an_image_whose_identity_changed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Create succeeded, but the file was replaced before rollback ran."""
        image, mount_point, config_path = _init_paths(tmp_path)
        state = MountState()

        def replace_image(argv: Any) -> None:
            # Allocate the replacement while the original still exists, then
            # take over the path atomically: ext4 hands a freshly unlinked
            # inode number straight back to the next create (APFS does not),
            # so an unlink-then-write swap would keep the same (st_dev,
            # st_ino) on Linux CI and make this test vacuous there.
            replacement = image.with_name(image.name + ".swap")
            replacement.write_bytes(b"someone else's image")
            os.replace(replacement, image)

        volume_run = FakeVolumeRunner(
            mount_state=state,
            results={"hdiutil attach": _failed("hdiutil attach", stderr="nope")},
            before={"hdiutil attach": replace_image},
        )
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=_init_prompt(),
            image_path=image,
            mount_point=mount_point,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert image.read_bytes() == b"someone else's image"
        assert "no longer the file this run created" in capsys.readouterr().err

    def test_rollback_removes_our_own_image_when_the_identity_matches(self, tmp_path: Path) -> None:
        state = MountState()
        volume_run = FakeVolumeRunner(
            mount_state=state, results={"hdiutil attach": _failed("hdiutil attach", stderr="nope")}
        )
        rc, image, _mp, _cfg, _vr = _run_init(tmp_path, volume_run=volume_run, mount_state=state)
        assert rc == 1
        assert not image.exists()

    @pytest.mark.parametrize("name", ["secure-home", "no-extension"])
    def test_image_without_a_suffix_gets_sparseimage_appended(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
    ) -> None:
        """HIGH-3: hdiutil appends the extension itself, so we must name the real file."""
        bare = tmp_path / "img" / name
        expected = bare.with_name(f"{name}.sparseimage")
        mount_point = tmp_path / "mnt"
        config_path = tmp_path / "cfg" / "secure-home.json"
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)

        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=_init_prompt(),
            image_path=bare,
            mount_point=mount_point,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 0
        assert expected.exists()
        assert not bare.exists()
        create = next(argv for argv, _, _ in volume_run.calls if argv[:2] == ("hdiutil", "create"))
        attach = next(argv for argv, _, _ in volume_run.calls if argv[:2] == ("hdiutil", "attach"))
        assert create[-1] == str(expected)
        assert str(expected) in attach
        loaded = load_config(config_path)
        assert loaded is not None
        assert loaded.backing == Backing(BACKING_DISK_IMAGE, expected)
        assert str(expected) in capsys.readouterr().err  # the emit_note

    def test_sparseimage_suffix_is_used_as_is(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc, image, _mp, config_path, _vr = _run_init(tmp_path)
        assert rc == 0
        assert image.name.endswith(".sparseimage")
        loaded = load_config(config_path)
        assert loaded is not None
        assert loaded.backing == Backing(BACKING_DISK_IMAGE, image)
        assert "hdiutil appends" not in capsys.readouterr().err

    @pytest.mark.parametrize("name", ["secure.sparsebundle", "secure.dmg", "secure.img"])
    def test_other_suffixes_are_refused(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str) -> None:
        """A ``.sparsebundle`` is a *directory* — ``unlink`` could never roll it back."""
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=tmp_path / "cfg" / "secure-home.json",
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            image_path=tmp_path / "img" / name,
            mount_point=tmp_path / "mnt",
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert not (tmp_path / "mnt").exists()
        err = capsys.readouterr().err
        assert ".sparseimage" in err
        assert "Nothing was created" in err

    def test_rollback_removes_the_image_directory_it_created(self, tmp_path: Path) -> None:
        """LOW-4: the image's parent directory is an artifact of this run too."""
        image_dir = tmp_path / "brand" / "new"
        state = MountState()
        volume_run = FakeVolumeRunner(
            mount_state=state, results={"hdiutil create": _failed("hdiutil create", stderr="nope")}
        )
        rc = secure_home_lifecycle_cli.init(
            config_path=tmp_path / "cfg" / "secure-home.json",
            platform="darwin",
            prompt_io=_init_prompt(),
            image_path=image_dir / "s.sparseimage",
            mount_point=tmp_path / "mnt",
            run=_probe_runner(tmp_path / "mnt"),
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert not image_dir.exists()

    def test_success_disarms_the_rollback_when_printing_explodes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MEDIUM-1: once the config is saved the volume belongs to the install.

        A ``BrokenPipeError`` from ``print`` (``... | head``) or a Ctrl-C during
        the summary must not delete the image out from under a live config.
        """

        def exploding_print(*args: Any, **kwargs: Any) -> None:
            raise BrokenPipeError("head closed the pipe")

        monkeypatch.setattr(secure_home_lifecycle_cli, "_print_init_success", exploding_print)
        image, mount_point, config_path = _init_paths(tmp_path)
        state = MountState()
        volume_run = FakeVolumeRunner(mount_state=state)

        with pytest.raises(BrokenPipeError):
            secure_home_lifecycle_cli.init(
                config_path=config_path,
                platform="darwin",
                prompt_io=_init_prompt(),
                image_path=image,
                mount_point=mount_point,
                run=_probe_runner(mount_point),
                volume_run=volume_run,
                ismount=state.ismount,
                home_dir=tmp_path,
            )
        assert image.exists()
        assert load_config(config_path) is not None
        assert "hdiutil detach" not in volume_run.actions
        assert state.ismount(str(mount_point))

    @pytest.mark.parametrize(
        ("passphrase", "accepted"), [("a" * 11, False), ("a" * 12, True), ("correct horse battery", True)]
    )
    def test_minimum_passphrase_length_is_twelve(self, tmp_path: Path, passphrase: str, accepted: bool) -> None:
        """MEDIUM-2: the image is copyable, so the passphrase is the whole defence."""
        rc, _image, _mp, _cfg, _vr = _run_init(tmp_path, prompt_io=_init_prompt(passphrase))
        assert rc == (0 if accepted else 1)

    @pytest.mark.parametrize("bad", ["pass\nword-long-enough", "pass\x00word-long-enough"])
    def test_untypable_passphrases_are_refused_before_any_tool_call(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], bad: str
    ) -> None:
        rc, image, _mp, _cfg, volume_run = _run_init(tmp_path, prompt_io=_init_prompt(bad))
        assert rc == 1
        assert volume_run.calls == []
        assert not image.exists()
        err = capsys.readouterr().err
        assert bad not in err
        assert "nothing was created" in err

    def test_mount_point_swapped_for_a_symlink_before_attach_is_refused(self, tmp_path: Path) -> None:
        """MEDIUM-5: ``ismount`` is False for a symlink, so a swap would also defeat rollback."""
        image, mount_point, config_path = _init_paths(tmp_path)
        elsewhere = tmp_path / "attacker"
        elsewhere.mkdir()
        state = MountState()

        class _SwappingPromptIO(ScriptedPromptIO):
            def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
                if mount_point.is_dir() and not mount_point.is_symlink():
                    mount_point.rmdir()
                    mount_point.symlink_to(elsewhere)
                return super().ask_password(label, default, description=description)

        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=_SwappingPromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            image_path=image,
            mount_point=mount_point,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        assert "hdiutil attach" not in volume_run.actions
        assert not image.exists()

    def test_rollback_detaches_by_the_device_node_the_attach_reported(self, tmp_path: Path) -> None:
        """MEDIUM-5b: detaching by dev node works even when ``ismount`` says False."""
        state = MountState()  # never flipped: models a mount ismount cannot see
        volume_run = FakeVolumeRunner(
            mount_state=None,
            results={"hdiutil attach": _attach_plist_result("/dev/disk9", "/some/where")},
        )
        image, mount_point, config_path = _init_paths(tmp_path)
        rc = secure_home_lifecycle_cli.init(
            config_path=config_path,
            platform="darwin",
            prompt_io=_init_prompt(),
            image_path=image,
            mount_point=mount_point,
            run=FakeRunner(diskutil_exc=OSError("diskutil exploded")),
            volume_run=volume_run,
            ismount=state.ismount,
            home_dir=tmp_path,
        )
        assert rc == 1
        detach_argv = next(argv for argv, _, _ in volume_run.calls if argv[:2] == ("hdiutil", "detach"))
        assert detach_argv[2] == "/dev/disk9"
        assert not image.exists()

    def test_filevault_off_warns_but_proceeds(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _image, mount_point, _config_path = _init_paths(tmp_path)
        run = FakeRunner(
            filevault_stdout="FileVault is Off.\n",
            diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID)),
        )
        rc, _image, _mp, _cfg, _vr = _run_init(tmp_path, run=run)
        assert rc == 0
        assert "FileVault is off" in capsys.readouterr().err

    def test_strict_mode_prints_the_lock_after_every_session_hint(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc, _image, _mp, _cfg, _vr = _run_init(tmp_path, mode=MODE_STRICT)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Strict mode" in out
        assert "secure-home unmount" in out

    def test_balanced_mode_prints_the_lock_when_done_hint(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc, _image, _mp, _cfg, _vr = _run_init(tmp_path, mode=MODE_BALANCED)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Lock it when done" in out


# -----------------------------------------------------------------------------
# mount
# -----------------------------------------------------------------------------
class TestMount:
    def _prepared(self, tmp_path: Path, *, native: bool = False) -> tuple[Path, Path, Path]:
        """A configured-but-locked secure home: the mount point exists and is
        EMPTY (``hermes-home`` lives inside the volume, so it only appears once
        the volume is mounted — that is what ``MountState(materialize_home=...)``
        models)."""
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        image = tmp_path / "secure.sparseimage"
        image.write_bytes(b"fake sparseimage")
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = _native_config(mount_point) if native else _image_config(mount_point, image)
        _write_config(config_path, config)
        return mount_point, image, config_path

    @staticmethod
    def _state(mounted: Sequence[Path] = ()) -> MountState:
        return MountState(mounted, materialize_home="hermes-home")

    def test_non_darwin_refuses(self, tmp_path: Path) -> None:
        rc = secure_home_lifecycle_cli.mount(
            config_path=tmp_path / "cfg.json",
            platform="linux",
            prompt_io=ScriptedPromptIO(),
            run=unused_runner,
            volume_run=unused_volume_runner,
            ismount=unused_ismount,
        )
        assert rc == 1

    def test_not_configured(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = secure_home_lifecycle_cli.mount(
            config_path=tmp_path / "missing.json",
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            run=unused_runner,
            volume_run=unused_volume_runner,
            ismount=unused_ismount,
        )
        assert rc == 1
        assert "secure-home init" in capsys.readouterr().err

    def test_unreadable_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        config_path = tmp_path / "cfg" / "secure-home.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("not json", encoding="utf-8")
        config_path.chmod(0o600)
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(),
            run=unused_runner,
            volume_run=unused_volume_runner,
            ismount=unused_ismount,
        )
        assert rc == 1
        assert "JSON" in capsys.readouterr().err

    def test_already_mounted_and_verified_is_a_no_op(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point, _image, config_path = self._prepared(tmp_path)
        (mount_point / "hermes-home").mkdir(mode=0o700)  # the volume is mounted, so its contents are visible
        prompt_io = ScriptedPromptIO()
        volume_run = FakeVolumeRunner()
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=prompt_io,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=lambda p: p == str(mount_point),
        )
        assert rc == 0
        assert prompt_io.password_labels == []
        assert volume_run.calls == []
        assert "already mounted and verified" in capsys.readouterr().out

    def test_already_mounted_but_wrong_volume_refuses_without_touching_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mount_point, _image, config_path = self._prepared(tmp_path)
        (mount_point / "hermes-home").mkdir(mode=0o700)
        prompt_io = ScriptedPromptIO()
        volume_run = FakeVolumeRunner()
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_OTHER_UUID)))
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=prompt_io,
            run=run,
            volume_run=volume_run,
            ismount=lambda p: p == str(mount_point),
        )
        assert rc == 1
        assert prompt_io.password_labels == []
        assert volume_run.calls == []
        assert "A different volume is mounted" in capsys.readouterr().err

    def test_v1_config_without_backing_refuses_with_a_readopt_hint(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        config_path = tmp_path / "cfg" / "secure-home.json"
        _write_config(config_path, _v1_config(mount_point))
        prompt_io = ScriptedPromptIO()
        volume_run = FakeVolumeRunner()
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=prompt_io,
            run=unused_runner,
            volume_run=volume_run,
            ismount=lambda p: False,
        )
        assert rc == 1
        assert prompt_io.password_labels == []
        assert volume_run.calls == []
        assert "adopt --force" in capsys.readouterr().err

    def test_missing_image_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _mount_point, image, config_path = self._prepared(tmp_path)
        image.unlink()
        volume_run = FakeVolumeRunner()
        prompt_io = ScriptedPromptIO(passwords=[_PASSPHRASE])
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=prompt_io,
            run=unused_runner,
            volume_run=volume_run,
            ismount=lambda p: False,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert prompt_io.password_labels == []
        assert str(image) in capsys.readouterr().err

    def test_symlinked_image_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _mount_point, image, config_path = self._prepared(tmp_path)
        image.unlink()
        target = tmp_path / "real.sparseimage"
        target.write_bytes(b"x")
        image.symlink_to(target)
        volume_run = FakeVolumeRunner()
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=unused_runner,
            volume_run=volume_run,
            ismount=lambda p: False,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert "regular file" in capsys.readouterr().err

    def test_empty_passphrase_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _mount_point, _image, config_path = self._prepared(tmp_path)
        volume_run = FakeVolumeRunner()
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[""]),
            run=unused_runner,
            volume_run=volume_run,
            ismount=lambda p: False,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert "must not be empty" in capsys.readouterr().err

    def test_attach_failure_reports_the_wrong_passphrase_hint(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _mount_point, _image, config_path = self._prepared(tmp_path)
        state = self._state()
        volume_run = FakeVolumeRunner(
            mount_state=state,
            results={"hdiutil attach": _failed("hdiutil attach", stderr="Authentication error")},
        )
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "wrong passphrase?" in err
        assert _PASSPHRASE not in err

    def test_happy_path_disk_image(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point, image, config_path = self._prepared(tmp_path)
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 0
        attach = next(call for call in volume_run.calls if call[0][:2] == ("hdiutil", "attach"))
        assert str(image) in attach[0]
        assert attach[2] == _PASSPHRASE
        assert _PASSPHRASE not in " ".join(attach[0])
        out = capsys.readouterr().out
        assert "Secure home mounted." in out
        assert str(mount_point / "hermes-home") in out

    def test_happy_path_native_apfs_volume(self, tmp_path: Path) -> None:
        mount_point, _image, config_path = self._prepared(tmp_path, native=True)
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 0
        argv, _timeout, stdin_input = volume_run.calls[0]
        assert argv[:3] == ("diskutil", "apfs", "unlockVolume")
        assert argv[3] == _UUID
        assert "-stdinpassphrase" in argv
        assert argv[argv.index("-mountpoint") + 1] == str(mount_point)
        assert stdin_input == _PASSPHRASE + "\n"

    def test_creates_the_mount_point_directory_when_missing(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"
        image = tmp_path / "secure.sparseimage"
        image.write_bytes(b"fake sparseimage")
        config_path = tmp_path / "cfg" / "secure-home.json"
        _write_config(config_path, _image_config(mount_point, image))
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 0
        assert mount_point.is_dir()
        assert stat.S_IMODE(mount_point.stat().st_mode) == 0o700

    def test_interrupt_at_the_passphrase_prompt_rolls_back_a_created_mount_dir(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"  # never created: `mount` must make it
        image = tmp_path / "secure.sparseimage"
        image.write_bytes(b"fake sparseimage")
        config_path = tmp_path / "cfg" / "secure-home.json"
        _write_config(config_path, _image_config(mount_point, image))
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)

        with pytest.raises(KeyboardInterrupt):
            secure_home_lifecycle_cli.mount(
                config_path=config_path,
                platform="darwin",
                prompt_io=ScriptedPromptIO(password_raises=KeyboardInterrupt()),
                run=unused_runner,
                volume_run=volume_run,
                ismount=state.ismount,
            )
        assert volume_run.calls == []
        assert not mount_point.exists()

    def test_interrupt_leaves_a_pre_existing_mount_dir_alone(self, tmp_path: Path) -> None:
        """Rollback removes only a directory *this run* created."""
        mount_point, _image, config_path = self._prepared(tmp_path)  # mount point already exists
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)

        with pytest.raises(KeyboardInterrupt):
            secure_home_lifecycle_cli.mount(
                config_path=config_path,
                platform="darwin",
                prompt_io=ScriptedPromptIO(password_raises=KeyboardInterrupt()),
                run=unused_runner,
                volume_run=volume_run,
                ismount=state.ismount,
            )
        assert mount_point.is_dir()

    def test_verification_failure_removes_a_mount_dir_this_run_created(self, tmp_path: Path) -> None:
        mount_point = tmp_path / "mnt"  # never created: `mount` must make it
        image = tmp_path / "secure.sparseimage"
        image.write_bytes(b"fake sparseimage")
        config_path = tmp_path / "cfg" / "secure-home.json"
        _write_config(config_path, _image_config(mount_point, image))
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))

        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=run,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.actions == ["hdiutil attach", "hdiutil detach"]
        assert not mount_point.exists()

    def test_relock_failure_says_the_volume_was_NOT_detached(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """MEDIUM-4: an operator told "detached again" stops looking."""
        mount_point, _image, config_path = self._prepared(tmp_path)
        state = self._state()
        volume_run = FakeVolumeRunner(
            mount_state=state, results={"hdiutil detach": _failed("hdiutil detach", stderr="Resource busy")}
        )
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=run,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "could NOT be detached again" in err
        assert f"hdiutil detach {mount_point}" in err
        assert "The volume was detached again." not in err

    def test_native_relock_failure_names_the_lock_command(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mount_point, _image, config_path = self._prepared(tmp_path, native=True)
        state = self._state()
        volume_run = FakeVolumeRunner(
            mount_state=state,
            mount_point=mount_point,
            results={"diskutil apfs lockVolume": _failed("diskutil apfs lockVolume", stderr="Resource busy")},
        )
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=run,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "could NOT be locked again" in err
        assert f"diskutil apfs lockVolume {_UUID}" in err

    def test_image_swapped_after_the_prompt_is_refused(self, tmp_path: Path) -> None:
        """LOW-1: the recorded image is re-checked after the passphrase is typed."""
        _mount_point, image, config_path = self._prepared(tmp_path)
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)

        class _SwappingPromptIO(ScriptedPromptIO):
            def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
                # Replacement allocated before the original goes away, so it
                # gets a distinct inode even on ext4 (see the init swap test).
                replacement = image.with_name(image.name + ".swap")
                replacement.write_bytes(b"a different image")
                os.replace(replacement, image)
                return super().ask_password(label, default, description=description)

        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=_SwappingPromptIO(passwords=[_PASSPHRASE]),
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.calls == []

    def test_mount_point_swapped_after_the_prompt_is_refused(self, tmp_path: Path) -> None:
        """MEDIUM-5a on the mount path."""
        mount_point, _image, config_path = self._prepared(tmp_path)
        elsewhere = tmp_path / "attacker"
        elsewhere.mkdir()
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)

        class _SwappingPromptIO(ScriptedPromptIO):
            def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
                mount_point.rmdir()
                mount_point.symlink_to(elsewhere)
                return super().ask_password(label, default, description=description)

        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=_SwappingPromptIO(passwords=[_PASSPHRASE]),
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.calls == []

    @pytest.mark.parametrize("bad", ["pass\nword-long-enough", "pass\x00word-long-enough"])
    def test_untypable_passphrase_is_refused_before_attaching(self, tmp_path: Path, bad: str) -> None:
        _mount_point, _image, config_path = self._prepared(tmp_path)
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[bad]),
            run=unused_runner,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.calls == []

    def test_relock_uses_the_device_node_when_the_attach_reported_one(self, tmp_path: Path) -> None:
        mount_point, _image, config_path = self._prepared(tmp_path)
        state = self._state()
        volume_run = FakeVolumeRunner(
            mount_state=state, results={"hdiutil attach": _attach_plist_result("/dev/disk9", str(mount_point))}
        )
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=run,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        detach_argv = next(argv for argv, _, _ in volume_run.calls if argv[:2] == ("hdiutil", "detach"))
        assert detach_argv[2] == "/dev/disk9"

    def test_verification_failure_after_attach_detaches_again(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mount_point, _image, config_path = self._prepared(tmp_path)
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state)
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=run,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.actions == ["hdiutil attach", "hdiutil detach"]
        assert not state.ismount(str(mount_point))
        err = capsys.readouterr().err
        assert "detached again" in err

    def test_native_verification_failure_locks_again(self, tmp_path: Path) -> None:
        mount_point, _image, config_path = self._prepared(tmp_path, native=True)
        state = self._state()
        volume_run = FakeVolumeRunner(mount_state=state, mount_point=mount_point)
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc = secure_home_lifecycle_cli.mount(
            config_path=config_path,
            platform="darwin",
            prompt_io=ScriptedPromptIO(passwords=[_PASSPHRASE]),
            run=run,
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.actions == ["diskutil apfs unlockVolume", "diskutil apfs lockVolume"]


# -----------------------------------------------------------------------------
# unmount
# -----------------------------------------------------------------------------
class TestUnmount:
    def _configured(self, tmp_path: Path, *, native: bool = False) -> tuple[Path, Path]:
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        image = tmp_path / "secure.sparseimage"
        image.write_bytes(b"fake sparseimage")
        config_path = tmp_path / "cfg" / "secure-home.json"
        config = _native_config(mount_point) if native else _image_config(mount_point, image)
        _write_config(config_path, config)
        return mount_point, config_path

    def test_non_darwin_refuses(self, tmp_path: Path) -> None:
        rc = secure_home_lifecycle_cli.unmount(
            config_path=tmp_path / "cfg.json",
            platform="linux",
            run=unused_runner,
            volume_run=unused_volume_runner,
            ismount=unused_ismount,
        )
        assert rc == 1

    def test_not_configured(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = secure_home_lifecycle_cli.unmount(
            config_path=tmp_path / "missing.json",
            platform="darwin",
            run=unused_runner,
            volume_run=unused_volume_runner,
            ismount=unused_ismount,
        )
        assert rc == 1
        assert "not configured" in capsys.readouterr().err

    def test_nothing_mounted_and_image_not_attached_is_success(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """MEDIUM-3: "locked" is now an answer the probe gave, not an assumption."""
        mount_point, config_path = self._configured(tmp_path)
        volume_run = FakeVolumeRunner()
        run = FakeRunner(hdiutil_result=hdiutil_result([]))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: False
        )
        assert rc == 0
        assert volume_run.calls == []
        out = capsys.readouterr().out
        assert "the image is not attached" in out
        assert str(mount_point) in out

    def test_image_attached_elsewhere_is_detached_by_device_node(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An image attached by Finder auto-mounts under /Volumes — not "locked"."""
        mount_point, config_path = self._configured(tmp_path)
        image = tmp_path / "secure.sparseimage"
        volume_run = FakeVolumeRunner()
        run = FakeRunner(hdiutil_result=_attached_image_result(image, "/dev/disk9", ["/Volumes/HermesSecure"]))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: False
        )
        assert rc == 0
        assert volume_run.calls[0][0] == ("hdiutil", "detach", "/dev/disk9")
        out = capsys.readouterr().out
        assert "attached at /Volumes/HermesSecure" in out
        assert str(mount_point) in out

    def test_image_attached_but_unmounted_reports_the_device_node(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _mount_point, config_path = self._configured(tmp_path)
        image = tmp_path / "secure.sparseimage"
        volume_run = FakeVolumeRunner()
        run = FakeRunner(hdiutil_result=_attached_image_result(image, "/dev/disk9", []))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: False
        )
        assert rc == 0
        assert "attached at /dev/disk9" in capsys.readouterr().out

    def test_image_attached_elsewhere_and_busy_without_force_refuses(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _mount_point, config_path = self._configured(tmp_path)
        image = tmp_path / "secure.sparseimage"
        volume_run = FakeVolumeRunner(results={"hdiutil detach": _failed("hdiutil detach", stderr="Resource busy")})
        run = FakeRunner(hdiutil_result=_attached_image_result(image, "/dev/disk9", ["/Volumes/X"]))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: False
        )
        assert rc == 1
        assert "--force" in capsys.readouterr().err

    def test_probe_failure_refuses_instead_of_claiming_locked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _mount_point, config_path = self._configured(tmp_path)
        volume_run = FakeVolumeRunner()
        run = FakeRunner(hdiutil_exc=OSError("hdiutil not found"))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: False
        )
        assert rc == 1
        assert volume_run.calls == []
        captured = capsys.readouterr()
        assert "Could not determine whether" in captured.err
        assert "locked" not in captured.out

    def test_native_unlocked_elsewhere_is_locked(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _mount_point, config_path = self._configured(tmp_path, native=True)
        volume_run = FakeVolumeRunner()
        run = FakeRunner(diskutil_result=diskutil_result({"Locked": False, "MountPoint": "/Volumes/Elsewhere"}))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: False
        )
        assert rc == 0
        assert volume_run.calls[0][0] == ("diskutil", "apfs", "lockVolume", _UUID)
        assert "attached at /Volumes/Elsewhere" in capsys.readouterr().out

    @pytest.mark.parametrize(
        ("plist", "expected"), [({"Locked": True}, "the volume is locked"), ({}, "the volume is not attached")]
    )
    def test_native_already_locked_or_absent_reports_honestly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], plist: dict[str, Any], expected: str
    ) -> None:
        _mount_point, config_path = self._configured(tmp_path, native=True)
        volume_run = FakeVolumeRunner()
        run = FakeRunner(diskutil_result=diskutil_result(plist))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: False
        )
        assert rc == 0
        assert volume_run.calls == []
        assert expected in capsys.readouterr().out

    def test_unknown_backing_with_nothing_mounted_says_it_did_not_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No recorded backing means no probe is possible — say that, don't imply a check."""
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        config_path = tmp_path / "cfg" / "secure-home.json"
        _write_config(config_path, _v1_config(mount_point))
        volume_run = FakeVolumeRunner()
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=unused_runner,
            volume_run=volume_run,
            ismount=lambda p: False,
        )
        assert rc == 0
        assert volume_run.calls == []
        assert "was not checked" in capsys.readouterr().out

    def test_uuid_mismatch_refuses_without_detaching(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point, config_path = self._configured(tmp_path)
        volume_run = FakeVolumeRunner()
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_OTHER_UUID)))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=run,
            volume_run=volume_run,
            ismount=lambda p: True,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert "not the configured secure home" in capsys.readouterr().err

    def test_noowners_volume_is_still_unmountable(self, tmp_path: Path) -> None:
        """``unmount`` runs the identity steps only — an acceptance concern
        (here: a ``noowners`` mount) must not strand a volume as un-lockable."""
        mount_point, config_path = self._configured(tmp_path)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(mount_state=state)
        run = FakeRunner(diskutil_result=diskutil_result(good_plist(mount_point, uuid=_UUID, ownership=False)))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=state.ismount
        )
        assert rc == 0

    def test_unknown_backing_refuses(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        config_path = tmp_path / "cfg" / "secure-home.json"
        _write_config(config_path, _v1_config(mount_point))
        volume_run = FakeVolumeRunner()
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=lambda p: True,
        )
        assert rc == 1
        assert volume_run.calls == []
        assert "adopt --force" in capsys.readouterr().err

    def test_busy_without_force_refuses_and_never_passes_force(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mount_point, config_path = self._configured(tmp_path)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(
            mount_state=state, results={"hdiutil detach": _failed("hdiutil detach", stderr="Resource busy")}
        )
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.actions == ["hdiutil detach"]
        assert all("-force" not in argv for argv, _, _ in volume_run.calls)
        assert "--force" in capsys.readouterr().err

    def test_busy_with_force_passes_force(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            force=True,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 0
        argv, _timeout, _input = volume_run.calls[0]
        assert argv == ("hdiutil", "detach", str(mount_point), "-force")

    def test_native_lock_busy_with_force_force_unmounts_then_locks(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path, native=True)
        state = MountState([mount_point])
        busy = _failed("diskutil apfs lockVolume", stderr="Resource busy")
        ok = subprocess.CompletedProcess(args=["diskutil"], returncode=0, stdout="", stderr="")
        results: dict[str, subprocess.CompletedProcess[str] | Exception] = {"diskutil apfs lockVolume": busy}
        volume_run = FakeVolumeRunner(mount_state=state, mount_point=mount_point, results=results)

        calls: list[str] = []
        original = volume_run.__call__

        def recording(argv: Any, *, timeout: float, input: str | None = None) -> subprocess.CompletedProcess[str]:
            action = " ".join(argv[:3]) if argv[0] == "diskutil" else " ".join(argv[:2])
            calls.append(action)
            if action == "diskutil apfs lockVolume" and calls.count(action) == 2:
                # The retry after the force-unmount succeeds.
                volume_run._results.pop(action, None)
                state.unmount(str(mount_point))
                return ok
            return original(argv, timeout=timeout, input=input)

        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            force=True,
            run=_probe_runner(mount_point),
            volume_run=recording,
            ismount=state.ismount,
        )
        assert rc == 0
        assert calls == [
            "diskutil apfs lockVolume",
            "diskutil unmount force",
            "diskutil apfs lockVolume",
        ]

    def test_native_lock_non_busy_failure_with_force_is_not_retried(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """LOW-4: only a *busy* failure earns the force-unmount escalation."""
        mount_point, config_path = self._configured(tmp_path, native=True)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(
            mount_state=state,
            mount_point=mount_point,
            results={"diskutil apfs lockVolume": _failed("diskutil apfs lockVolume", stderr="not an APFS volume")},
        )
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            force=True,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        assert volume_run.actions == ["diskutil apfs lockVolume"]
        assert "not an APFS volume" in capsys.readouterr().err

    def test_force_unmount_succeeds_but_the_lock_retry_fails(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """LOW-4: the volume is at least unmounted — warn, then let the post-check rule."""
        mount_point, config_path = self._configured(tmp_path, native=True)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(
            mount_state=state,
            mount_point=mount_point,
            results={"diskutil apfs lockVolume": _failed("diskutil apfs lockVolume", stderr="Resource busy")},
        )
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            force=True,
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 0  # `diskutil unmount force` did clear the mount
        assert volume_run.actions == [
            "diskutil apfs lockVolume",
            "diskutil unmount force",
            "diskutil apfs lockVolume",
        ]
        assert "force-unmounted but could not be locked" in capsys.readouterr().err

    def test_non_uuid_verification_failure_is_reported_verbatim(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """LOW-4: a probe failure is not a "foreign volume" refusal."""
        _mount_point, config_path = self._configured(tmp_path)
        volume_run = FakeVolumeRunner()
        run = FakeRunner(diskutil_exc=OSError("diskutil exploded"))
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path, platform="darwin", run=run, volume_run=volume_run, ismount=lambda p: True
        )
        assert rc == 1
        assert volume_run.calls == []
        err = capsys.readouterr().err
        assert "Could not verify the mounted volume" in err
        assert "not the configured secure home" not in err

    def test_non_busy_detach_failure_is_reported_without_the_force_advice(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mount_point, config_path = self._configured(tmp_path)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(
            mount_state=state, results={"hdiutil detach": _failed("hdiutil detach", stderr="no such device")}
        )
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "no such device" in err
        assert "--force" not in err

    def test_still_mounted_after_the_attempt_fails(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point, config_path = self._configured(tmp_path)
        volume_run = FakeVolumeRunner()  # rc 0 but no MountState -> nothing changes
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=lambda p: True,
        )
        assert rc == 1
        assert "still mounted" in capsys.readouterr().err

    def test_happy_path_disk_image(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        mount_point, config_path = self._configured(tmp_path)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(mount_state=state)
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 0
        assert volume_run.actions == ["hdiutil detach"]
        assert "Secure home locked." in capsys.readouterr().out

    def test_happy_path_native_apfs_volume(self, tmp_path: Path) -> None:
        mount_point, config_path = self._configured(tmp_path, native=True)
        state = MountState([mount_point])
        volume_run = FakeVolumeRunner(mount_state=state, mount_point=mount_point)
        rc = secure_home_lifecycle_cli.unmount(
            config_path=config_path,
            platform="darwin",
            run=_probe_runner(mount_point),
            volume_run=volume_run,
            ismount=state.ismount,
        )
        assert rc == 0
        assert volume_run.calls[0][0] == ("diskutil", "apfs", "lockVolume", _UUID)


# -----------------------------------------------------------------------------
# argparse delegation wiring
# -----------------------------------------------------------------------------
class TestParserDelegation:
    def test_handle_init_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, argparse.Namespace] = {}

        def fake_cli_init(args: argparse.Namespace) -> int:
            captured["args"] = args
            return 7

        monkeypatch.setattr(secure_home_lifecycle_cli, "cli_init", fake_cli_init)
        ns = argparse.Namespace(image=None)
        assert _secure_home_parsers._handle_secure_home_init(ns) == 7
        assert captured["args"] is ns

    def test_handle_mount_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, argparse.Namespace] = {}

        def fake_cli_mount(args: argparse.Namespace) -> int:
            captured["args"] = args
            return 7

        monkeypatch.setattr(secure_home_lifecycle_cli, "cli_mount", fake_cli_mount)
        ns = argparse.Namespace()
        assert _secure_home_parsers._handle_secure_home_mount(ns) == 7
        assert captured["args"] is ns

    def test_handle_unmount_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, argparse.Namespace] = {}

        def fake_cli_unmount(args: argparse.Namespace) -> int:
            captured["args"] = args
            return 7

        monkeypatch.setattr(secure_home_lifecycle_cli, "cli_unmount", fake_cli_unmount)
        ns = argparse.Namespace(force=True)
        assert _secure_home_parsers._handle_secure_home_unmount(ns) == 7
        assert captured["args"] is ns

    def test_parser_defaults_match_the_module_constants(self) -> None:
        """The argparse defaults are literals (the parser must stay import-light);
        this pins them to the ceremony module's constants so they cannot drift."""
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        _secure_home_parsers.add_secure_home(sub)
        ns = parser.parse_args(["secure-home", "init"])
        assert ns.size == secure_home_lifecycle_cli.DEFAULT_SIZE
        assert ns.volname == secure_home_lifecycle_cli.DEFAULT_VOLUME_NAME


class TestCliDefaultsResolution:
    """``cli_*`` -> the public ceremony API, with production defaults resolved."""

    def test_cli_init_maps_namespace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}
        sentinel = object()

        def fake_init(**kwargs: object) -> int:
            captured.update(kwargs)
            return 7

        monkeypatch.setattr(secure_home_lifecycle_cli, "init", fake_init)
        monkeypatch.setattr(secure_home_lifecycle_cli, "resolve_config_path", lambda: tmp_path / "cfg.json")
        monkeypatch.setattr(secure_home_lifecycle_cli, "PromptToolkitIO", lambda: sentinel)

        rc = secure_home_lifecycle_cli.cli_init(
            argparse.Namespace(
                image=str(tmp_path / "i.sparseimage"),
                mount_point=str(tmp_path / "m"),
                size="9g",
                volname="Vol",
                mode=MODE_STRICT,
                force=True,
            )
        )
        assert rc == 7
        assert captured["config_path"] == tmp_path / "cfg.json"
        assert captured["platform"] == sys.platform
        assert captured["prompt_io"] is sentinel
        assert captured["image_path"] == tmp_path / "i.sparseimage"
        assert captured["mount_point"] == tmp_path / "m"
        assert captured["size"] == "9g"
        assert captured["volume_name"] == "Vol"
        assert captured["mode"] == MODE_STRICT
        assert captured["force"] is True

    def test_cli_init_defaults_when_flags_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_init(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(secure_home_lifecycle_cli, "init", fake_init)
        monkeypatch.setattr(secure_home_lifecycle_cli, "resolve_config_path", lambda: tmp_path / "cfg.json")
        monkeypatch.setattr(secure_home_lifecycle_cli, "PromptToolkitIO", lambda: object())

        secure_home_lifecycle_cli.cli_init(argparse.Namespace())
        assert captured["image_path"] is None
        assert captured["mount_point"] is None
        assert captured["size"] == secure_home_lifecycle_cli.DEFAULT_SIZE
        assert captured["volume_name"] == secure_home_lifecycle_cli.DEFAULT_VOLUME_NAME
        assert captured["mode"] is None
        assert captured["force"] is False

    def test_cli_mount_maps_namespace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}
        sentinel = object()

        def fake_mount(**kwargs: object) -> int:
            captured.update(kwargs)
            return 7

        monkeypatch.setattr(secure_home_lifecycle_cli, "mount", fake_mount)
        monkeypatch.setattr(secure_home_lifecycle_cli, "resolve_config_path", lambda: tmp_path / "cfg.json")
        monkeypatch.setattr(secure_home_lifecycle_cli, "PromptToolkitIO", lambda: sentinel)

        assert secure_home_lifecycle_cli.cli_mount(argparse.Namespace()) == 7
        assert captured["config_path"] == tmp_path / "cfg.json"
        assert captured["platform"] == sys.platform
        assert captured["prompt_io"] is sentinel

    def test_cli_unmount_maps_namespace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_unmount(**kwargs: object) -> int:
            captured.update(kwargs)
            return 7

        monkeypatch.setattr(secure_home_lifecycle_cli, "unmount", fake_unmount)
        monkeypatch.setattr(secure_home_lifecycle_cli, "resolve_config_path", lambda: tmp_path / "cfg.json")

        assert secure_home_lifecycle_cli.cli_unmount(argparse.Namespace(force=True)) == 7
        assert captured["config_path"] == tmp_path / "cfg.json"
        assert captured["platform"] == sys.platform
        assert captured["force"] is True

    def test_cli_unmount_force_defaults_false(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_unmount(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(secure_home_lifecycle_cli, "unmount", fake_unmount)
        monkeypatch.setattr(secure_home_lifecycle_cli, "resolve_config_path", lambda: tmp_path / "cfg.json")

        secure_home_lifecycle_cli.cli_unmount(argparse.Namespace())
        assert captured["force"] is False


# -----------------------------------------------------------------------------
# no passphrase surface anywhere
# -----------------------------------------------------------------------------
class TestNoPassphraseSurface:
    def test_no_parser_option_accepts_a_passphrase(self) -> None:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        _secure_home_parsers.add_secure_home(sub)
        secure_home = sub.choices["secure-home"]
        nested = next(a for a in secure_home._actions if isinstance(a, argparse._SubParsersAction))
        for verb, verb_parser in nested.choices.items():
            options = [option for action in verb_parser._actions for option in action.option_strings]
            assert not [o for o in options if "pass" in o.lower()], f"{verb} exposes a passphrase flag: {options}"

    def test_no_ceremony_module_reads_the_process_environment(self) -> None:
        """No environment variable can supply (or leak) the passphrase, in any of
        the four modules the ceremonies are split across."""
        from mordred_hermes.wizard import _secure_home_ceremony, _secure_home_unmount, _secure_home_volume

        for module in (secure_home_lifecycle_cli, _secure_home_ceremony, _secure_home_unmount, _secure_home_volume):
            source = Path(module.__file__ or "").read_text(encoding="utf-8")
            assert "os.environ" not in source, module.__name__
            assert "getenv" not in source, module.__name__
