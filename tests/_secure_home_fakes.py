"""Shared secure-home test doubles for the Phase 2 ceremony tests.

``tests/test_wizard_secure_home_lifecycle_cli.py`` needs four things at once:
a scripted :class:`~mordred_hermes.wizard._prompt_io.PromptIO`, a recording
``VolumeRunner`` whose scripted results can also flip the mount state a fake
``os.path.ismount`` reads, a read-only ``SubprocessRunner`` for the identity
chain, and the ``diskutil``/``hdiutil`` plist builders. The first two are new;
the last two are deliberate *copies* of the private helpers in
``tests/test_wizard_secure_home_cli.py`` — that module's own fakes are left
untouched so a Phase 2 change here can never silently alter what the Phase 1
suite asserts.

Imported like ``tests/_keyvault_fakes.py`` (``from ._secure_home_fakes import
...``). Not a ``test_*`` module, so pytest does not collect it.
"""

from __future__ import annotations

import contextlib
import plistlib
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

# -----------------------------------------------------------------------------
# Prompt IO
# -----------------------------------------------------------------------------


class ScriptedPromptIO:
    """Full :class:`PromptIO` implementation driven by pre-recorded answers.

    ``ask_password`` pops from ``passwords`` in order and records every label,
    so a test can assert both *how many* prompts happened and *which* ones.
    Running out of scripted passwords is an ``AssertionError``, never a silent
    empty string — an unexpected extra prompt is a bug, not a passing test.
    The other methods answer from a per-label mapping and fall back to the
    caller's own default, so a prompt a test does not care about stays silent.
    """

    def __init__(
        self,
        *,
        passwords: Sequence[str] = (),
        choices: Mapping[str, str] | None = None,
        texts: Mapping[str, str] | None = None,
        bools: Mapping[str, bool] | None = None,
        multis: Mapping[str, Sequence[str]] | None = None,
        password_raises: BaseException | None = None,
    ) -> None:
        #: Raised (after recording the label) instead of answering a password
        #: prompt — models Ctrl-C, Ctrl-D, or a --non-interactive abort at a
        #: real TTY, all of which are BaseException/RuntimeError, not a value.
        self.password_raises = password_raises
        self.passwords = list(passwords)
        self.choices = dict(choices or {})
        self.texts = dict(texts or {})
        self.bools = dict(bools or {})
        self.multis = {label: tuple(values) for label, values in (multis or {}).items()}
        self.password_labels: list[str] = []
        self.choice_labels: list[str] = []

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        self.choice_labels.append(label)
        return self.choices.get(label, default)

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return self.texts.get(label, default)

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return self.bools.get(label, default)

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        return self.multis.get(label, tuple(default))

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        self.password_labels.append(label)
        if self.password_raises is not None:
            raise self.password_raises
        if not self.passwords:
            raise AssertionError(f"ScriptedPromptIO ran out of scripted passwords at {label!r}")
        return self.passwords.pop(0)


# -----------------------------------------------------------------------------
# Volume runner
# -----------------------------------------------------------------------------


class MountState:
    """Mutable mount table shared by :class:`FakeVolumeRunner` and a fake ``ismount``.

    A ceremony's control flow depends on the mount state *changing* mid-run
    (attach, then verify; detach, then post-check), so a constant ``ismount``
    lambda cannot exercise it. Scripted attach/unlock/detach/lock calls flip
    this table, and ``ismount`` reads it.
    """

    def __init__(self, mounted: Sequence[str | Path] = (), *, materialize_home: str | None = None) -> None:
        self.mounted: set[str] = set()
        #: When set, mounting also materialises ``<mount>/<materialize_home>``
        #: and unmounting removes it again — the volume's contents only exist
        #: while it is mounted, which is what the identity chain checks.
        self.materialize_home = materialize_home
        for path in mounted:
            self.mount(path)

    def ismount(self, path: str) -> bool:
        return path in self.mounted

    def mount(self, path: str | Path) -> None:
        self.mounted.add(str(path))
        if self.materialize_home:
            with contextlib.suppress(OSError):
                (Path(path) / self.materialize_home).mkdir(mode=0o700, exist_ok=True)

    def unmount(self, path: str | Path) -> None:
        self.mounted.discard(str(path))
        if self.materialize_home:
            with contextlib.suppress(OSError):
                (Path(path) / self.materialize_home).rmdir()


def volume_action(argv: Sequence[str]) -> str:
    """Canonical scripting key for a volume-mutating argv.

    ``diskutil`` needs three tokens (``diskutil apfs unlockVolume`` vs.
    ``diskutil apfs lockVolume`` share their first two), ``hdiutil`` needs
    two.
    """
    if argv and argv[0] == "diskutil":
        return " ".join(argv[:3])
    return " ".join(argv[:2])


def _flag_value(argv: Sequence[str], flag: str) -> str | None:
    for index, token in enumerate(argv):
        if token == flag and index + 1 < len(argv):
            return argv[index + 1]
    return None


class FakeVolumeRunner:
    """Recording ``VolumeRunner``: scripted per :func:`volume_action`, records every call.

    Every call is appended to ``calls`` as ``(argv, timeout, input)`` so the
    passphrase-only-via-stdin property is directly assertable. An unscripted
    action succeeds with rc 0 (the common case); a scripted
    ``CompletedProcess`` or ``Exception`` overrides that per action.

    A successful ``hdiutil create`` also writes a placeholder file at the
    image path (``create_files=True``), so rollback assertions such as "the
    image this run created was removed again" test something real rather than
    a path that never existed in the first place.
    """

    def __init__(
        self,
        *,
        results: Mapping[str, subprocess.CompletedProcess[str] | BaseException] | None = None,
        mount_state: MountState | None = None,
        mount_point: str | Path | None = None,
        create_files: bool = True,
        before: Mapping[str, Callable[[Sequence[str]], None]] | None = None,
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], float, str | None]] = []
        self._results = dict(results or {})
        #: Ran after the call is recorded but before the scripted result — lets
        #: a test model a tool that had already written something when it was
        #: interrupted (a partially created disk image).
        self._before = dict(before or {})
        self._mount_state = mount_state
        self._mount_point = str(mount_point) if mount_point is not None else None
        self._create_files = create_files

    @property
    def actions(self) -> list[str]:
        return [volume_action(argv) for argv, _, _ in self.calls]

    def __call__(
        self, argv: Sequence[str], *, timeout: float, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((tuple(argv), timeout, input))
        action = volume_action(argv)
        hook = self._before.get(action)
        if hook is not None:
            hook(argv)
        scripted = self._results.get(action)
        if isinstance(scripted, BaseException):
            raise scripted
        result = scripted if scripted is not None else subprocess.CompletedProcess(list(argv), 0, "", "")
        if result.returncode == 0:
            if action == "hdiutil create" and self._create_files:
                Path(argv[-1]).write_bytes(b"fake sparseimage")
            self._apply_mount_effect(action, argv)
        return result

    def _apply_mount_effect(self, action: str, argv: Sequence[str]) -> None:
        if self._mount_state is None:
            return
        if action in {"hdiutil attach", "diskutil apfs unlockVolume"}:
            target = _flag_value(argv, "-mountpoint") or self._mount_point
            if target is not None:
                self._mount_state.mount(target)
        elif action == "hdiutil detach":
            self._mount_state.unmount(argv[2])
        elif action == "diskutil unmount force":
            self._mount_state.unmount(argv[3])
        elif action == "diskutil apfs lockVolume" and self._mount_point is not None:
            self._mount_state.unmount(self._mount_point)


def unused_volume_runner(
    argv: Sequence[str], *, timeout: float, input: str | None = None
) -> subprocess.CompletedProcess[str]:
    raise AssertionError(f"no volume-mutating command should have been invoked: {argv}")


# -----------------------------------------------------------------------------
# Read-only probe runner + plist payloads (copies of the Phase 1 suite's fakes)
# -----------------------------------------------------------------------------


class FakeRunner:
    """Dispatches on ``argv[0]`` — fdesetup / diskutil / hdiutil — each scripted independently."""

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


def unused_runner(argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    raise AssertionError(f"subprocess should not have been invoked: {argv}")


def unused_ismount(path: str) -> bool:
    raise AssertionError(f"ismount should not have been called: {path}")


def diskutil_result(
    plist: dict[str, Any], *, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    argv = ("diskutil", "info", "-plist", "<mount>")
    return subprocess.CompletedProcess(
        args=list(argv), returncode=returncode, stdout=plistlib.dumps(plist).decode(), stderr=stderr
    )


def hdiutil_image(
    dev_entries: Sequence[str], *, encrypted: bool | None, image_path: str | None = None
) -> dict[str, Any]:
    entities: list[dict[str, Any]] = [{"dev-entry": entry} for entry in dev_entries]
    image: dict[str, Any] = {"system-entities": entities}
    if encrypted is not None:
        image["image-encrypted"] = encrypted
    if image_path is not None:
        image["image-path"] = image_path
    return image


def hdiutil_result(images: Sequence[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
    argv = ("hdiutil", "info", "-plist")
    return subprocess.CompletedProcess(
        args=list(argv), returncode=0, stdout=plistlib.dumps({"images": list(images)}).decode(), stderr=""
    )


def good_plist(
    mount_point: Path,
    *,
    uuid: str,
    filesystem: str | None = "apfs",
    device_node: str | None = "/dev/disk3s2",
    reported_mount_point: str | None = None,
    proper: bool | None = True,
    ownership: bool | None = True,
) -> dict[str, Any]:
    """The canonical "good volume" ``diskutil info -plist`` payload."""
    plist: dict[str, Any] = {
        "MountPoint": reported_mount_point if reported_mount_point is not None else str(mount_point)
    }
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
