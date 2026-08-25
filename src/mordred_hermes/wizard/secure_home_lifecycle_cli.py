"""``hermes-mordred secure-home {init,mount,unmount}`` — the volume ceremonies.

Phase 1's ``secure-home`` verbs performed **zero** volume operations: the
operator created, mounted and unmounted the encrypted volume by hand and
``adopt`` merely recorded it. This module is the Phase 2 addition that
automates that ceremony. It owns policy and sequencing only — the actual
``hdiutil``/``diskutil`` invocations live in :mod:`._secure_home_volume`, the
identity chain in :mod:`._secure_home_probe`, the persisted pointer in
:mod:`._secure_home_paths`, the shared preparation steps in
:mod:`._secure_home_ceremony`, and the lock/detach half in
:mod:`._secure_home_unmount` — so "what we do" and "how we call the tool" stay
separately reviewable.

**The passphrase.** There is no ``--passphrase`` flag and no environment
variable, by design: both would put an operator's volume key in ``ps`` output,
shell history, or a CI log. It is read only from
:meth:`PromptIO.ask_password` (whose production implementation already
requires a TTY) and handed only to :mod:`._secure_home_volume`, which pipes it
to the tool over stdin with a UTF-8-pinned encoding. It is never printed,
never logged, and never included in an exception message. Python cannot
zeroize a ``str``, so the local is ``del``-ed as soon as the last tool call
returns — best effort, documented as such rather than claimed as a guarantee.

**Destructiveness.** ``init`` never overwrites an existing image, not even
with ``--force`` (which replaces the *config*, not the volume), and never
deletes anything it did not create in this same run. Every artifact it makes
is tracked in :class:`_InitArtifacts`, and the image is additionally recorded
by ``(st_dev, st_ino)`` so a rollback provably unlinks *our* file and not one
a racing process created in the same path during the human-speed prompts.
Once the config is written the rollback disarms entirely: deleting the image
out from under a saved config would wedge the installation, which is worse
than leaving a stray file. ``mount`` re-runs the full :func:`verify_home`
chain *after* attaching and puts the volume back when it fails — saying so
only when the put-back actually succeeded.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import _term
from ._secure_home_ceremony import (
    DIR_MODE,
    PathIdentity,
    Refusal,
    error_message,
    load_required_config,
    prepare_mount_point,
    recheck_image_identity,
    recheck_mount_point,
    remove_created_mount_dir,
    require_backing,
    require_image_file,
)
from ._secure_home_paths import (
    BACKING_DISK_IMAGE,
    MODE_BALANCED,
    MODE_STRICT,
    MODES,
    Backing,
    SecureHomeConfig,
    SecureHomeConfigError,
    resolve_config_path,
)
from ._secure_home_probe import (
    DEFAULT_RUNNER,
    FileVaultState,
    SecureHomeVerificationError,
    SubprocessRunner,
    VerifiedHome,
    filevault_status,
    verify_home,
)
from ._secure_home_unmount import relock_after_failed_verification, unmount_with_config
from ._secure_home_volume import (
    DEFAULT_VOLUME_RUNNER,
    SecureHomeVolumeError,
    VolumeRunner,
    attach_image,
    create_encrypted_image,
    detach,
    unlock_native_volume,
)
from .configure import PromptIO, PromptToolkitIO
from .secure_home_cli import (
    _DARWIN,
    _load_config_safe,
    _refuse_existing_config,
    _refuse_not_macos,
    _to_absolute,
    record_volume,
)

__all__ = [
    "DEFAULT_SIZE",
    "DEFAULT_VOLUME_NAME",
    "IMAGE_SUFFIX",
    "MIN_PASSPHRASE_LENGTH",
    "cli_init",
    "cli_mount",
    "cli_unmount",
    "default_image_path",
    "default_mount_point",
    "init",
    "mount",
    "unmount",
]

#: Sparse images allocate lazily, so this is a ceiling, not a reservation —
#: big enough that an operator never has to think about resizing a Hermes home.
DEFAULT_SIZE: Final[str] = "4g"
DEFAULT_VOLUME_NAME: Final[str] = "HermesSecure"

#: The passphrase is not one factor among several — it is the *only* control
#: on a file that can be copied to another machine and attacked offline at the
#: attacker's leisure, with no lockout, no rate limit and no Secure Enclave in
#: the way. A short one is a real compromise of the volume, not a UX nit, so
#: the floor is set where a memorable multi-word passphrase comfortably lands.
MIN_PASSPHRASE_LENGTH: Final[int] = 12

#: ``man hdiutil``: image-creating verbs append the correct extension when it
#: is absent, *and* the creation engine reads the extension to choose the
#: format. So the name we pass has to be the name hdiutil will actually write,
#: or every later step (attach, config, rollback) addresses a different file.
IMAGE_SUFFIX: Final[str] = ".sparseimage"

_APP_SUPPORT_PARTS: Final[tuple[str, ...]] = ("Library", "Application Support", "hermes-mordred")

_MODE_DESCRIPTIONS: Final[Mapping[str, str]] = {
    MODE_BALANCED: "unlock once per login/first launch; stays mounted while Hermes runs (recommended)",
    MODE_STRICT: "unlock explicitly each session and lock it again with `secure-home unmount`",
}


def default_image_path(home: Path) -> Path:
    """``~/Library/Application Support/hermes-mordred/secure-home.sparseimage``."""
    return home.joinpath(*_APP_SUPPORT_PARTS) / "secure-home.sparseimage"


def default_mount_point(home: Path) -> Path:
    """``~/Library/Application Support/hermes-mordred/secure-home``."""
    return home.joinpath(*_APP_SUPPORT_PARTS) / "secure-home"


def _refuse_untypable_passphrase(passphrase: str, consequence: str) -> None:
    """Refuse a passphrase whose bytes the tools' stdin framing would truncate.

    Checked here, before any tool runs, so the operator gets a clear sentence
    instead of the volume layer's ``ValueError``. Never echoes the value.
    """
    if "\n" in passphrase:
        raise Refusal(f"The passphrase must not contain a line break — {consequence}.")
    if "\x00" in passphrase:
        raise Refusal(f"The passphrase must not contain a NUL character — {consequence}.")


# -----------------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------------
@dataclass
class _InitArtifacts:
    """Exactly what this ``init`` run created, so rollback can undo that and nothing else."""

    image: Path
    mount_point: Path
    created_mount_dir: bool = False
    created_image_dir: Path | None = None
    created_image: bool = False
    #: ``(st_dev, st_ino)`` of the image *we* created, captured right after
    #: ``hdiutil create`` returned. ``None`` means we never got to stat it.
    image_identity: PathIdentity | None = None
    attached: bool = False
    device_node: str | None = None
    #: Set once the config is on disk. From that moment the volume belongs to
    #: the installation, not to this run, and rollback must not touch it.
    recorded: bool = False


def _warn_replacing_config(config_path: Path) -> None:
    existing, _ = _load_config_safe(config_path)
    if existing is not None:
        _term.emit_warn(
            f"replacing the existing secure-home config for {existing.mount_point}; "
            "the previous volume/image is left untouched"
        )


def _normalize_image_path(image: Path) -> Path:
    """Make the image name the exact name ``hdiutil create`` will write.

    ``hdiutil`` appends :data:`IMAGE_SUFFIX` when the name has no extension —
    so ``--image ~/x`` would create ``~/x.sparseimage`` while we went on to
    attach, record and roll back ``~/x``, leaving the real image orphaned. And
    it *switches format* on the extension: ``.sparsebundle`` produces a
    directory bundle that ``unlink`` cannot remove, so rollback would silently
    fail. Only the one suffix we actually create is accepted.
    """
    suffix = image.suffix
    if not suffix:
        normalized = image.with_name(image.name + IMAGE_SUFFIX)
        _term.emit_note(f"creating {normalized} (hdiutil appends the {IMAGE_SUFFIX} extension itself)")
        return normalized
    if suffix.casefold() == IMAGE_SUFFIX:
        return image
    raise Refusal(
        f"secure-home init creates {IMAGE_SUFFIX} files, but the image name ends in {suffix!r}; "
        f"name it *{IMAGE_SUFFIX} or omit the extension. Nothing was created."
    )


def _refuse_occupied_image(image: Path) -> None:
    if os.path.lexists(image):
        raise Refusal(
            f"{image} already exists — secure-home init never overwrites an existing image; "
            "pick another --image or remove it yourself. Nothing was created."
        )


def _ensure_image_dir(directory: Path) -> Path | None:
    """Create the image's directory chain; return the leaf iff this call made it."""
    directory_created = not directory.exists()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if directory_created:
            os.chmod(directory, DIR_MODE)  # only narrow a directory we made ourselves
    except OSError as exc:
        raise Refusal(f"could not create the image directory {directory}: {exc}") from exc
    return directory if directory_created else None


def _prepare_image_target(artifacts: _InitArtifacts) -> None:
    artifacts.image = _normalize_image_path(artifacts.image)
    _refuse_occupied_image(artifacts.image)
    artifacts.created_image_dir = _ensure_image_dir(artifacts.image.parent)


def _resolve_mode(mode: str | None, prompt_io: PromptIO) -> str:
    chosen = mode or prompt_io.ask_choice("Secure-home mode", MODES, MODE_BALANCED, descriptions=_MODE_DESCRIPTIONS)
    if chosen not in MODES:
        raise Refusal(f"unknown secure-home mode {chosen!r} (expected one of {', '.join(MODES)}). Nothing was created.")
    return chosen


def _collect_new_passphrase(prompt_io: PromptIO) -> str:
    """Ask twice and require a match — a typo here would lock the operator out of a fresh volume."""
    passphrase = prompt_io.ask_password("Choose the secure-home volume passphrase")
    if not passphrase:
        raise Refusal("Passphrase must not be empty — nothing was created.")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise Refusal(
            f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters — it is the only thing protecting "
            "an image file that can be copied and attacked offline. Nothing was created."
        )
    _refuse_untypable_passphrase(passphrase, "nothing was created")
    if passphrase != prompt_io.ask_password("Re-enter the passphrase"):
        raise Refusal("Passphrases do not match — nothing was created.")
    return passphrase


def _warn_if_filevault_off(run: SubprocessRunner) -> None:
    """Informational only — secure-home is worth having either way, so this never blocks."""
    if filevault_status(run=run) is FileVaultState.OFF:
        _term.emit_warn(
            "FileVault is off on this Mac. secure-home still encrypts the Hermes home, but the rest of the "
            "disk (caches, swap, logs, and anything Hermes wrote before today) stays readable at rest."
        )


def _detach_best_effort(target: Path, *, volume_run: VolumeRunner) -> None:
    """Detach during rollback: retry with ``-force``, and if that fails say what to run by hand."""
    try:
        detach(target, run=volume_run)
        return
    except SecureHomeVolumeError:
        pass
    try:
        detach(target, force=True, run=volume_run)
    except SecureHomeVolumeError as exc:
        _term.emit_warn(
            f"could not detach {target} while rolling back ({exc.message}); detach it yourself: hdiutil detach {target}"
        )


def _image_identity(image: Path) -> PathIdentity | None:
    try:
        metadata = image.lstat()
    except OSError:
        return None
    return (metadata.st_dev, metadata.st_ino)


def _image_is_ours(artifacts: _InitArtifacts) -> bool:
    """Is the file at the image path still the one ``hdiutil create`` made for us?

    The ``lexists`` gate that reserved this path ran *before* the mode and
    passphrase prompts — a human-speed window in which a concurrent ``init``
    (or anything else) can create that file, making our own create fail with
    "File exists". Unlinking on that path would delete the other run's image.
    Comparing inode identity is what makes the rollback provably ours.

    ``image_identity is None`` means ``hdiutil create`` was interrupted before
    it returned, so we never got to stat the result. That window is
    milliseconds wide and opens immediately after a ``lexists`` that found
    nothing, so anything there now is overwhelmingly our own partial image —
    the single documented place this rollback acts without identity proof,
    because leaving a half-written encrypted image behind is the worse
    outcome.
    """
    if artifacts.image_identity is None:
        return True
    return _image_identity(artifacts.image) == artifacts.image_identity


def _unlink_our_image(artifacts: _InitArtifacts) -> None:
    if not artifacts.created_image:
        return
    if not _image_is_ours(artifacts):
        _term.emit_warn(
            f"leaving {artifacts.image} in place during rollback: it is no longer the file this run created, "
            "so another process appears to own it now."
        )
        return
    try:
        artifacts.image.unlink(missing_ok=True)
    except OSError as exc:
        _term.emit_warn(f"could not remove the image this run created ({artifacts.image}): {exc}")


def _rollback_init(artifacts: _InitArtifacts, *, volume_run: VolumeRunner, ismount: Callable[[str], bool]) -> None:
    """Undo exactly this run's artifacts, newest first. Never touches anything it did not create."""
    if artifacts.recorded:
        # The config names this volume now. Removing the image would leave a
        # configured-but-unopenable secure home — wedged, and harder to
        # recover from than the stray artifact this would have cleaned up.
        return
    if artifacts.attached:
        # `attached` is set *before* the attach call so an interrupt mid-call
        # is covered; a device node proves it really came up, and ismount is
        # the fallback when the attach never reported one.
        target = Path(artifacts.device_node) if artifacts.device_node else artifacts.mount_point
        if artifacts.device_node is not None or ismount(str(artifacts.mount_point)):
            _detach_best_effort(target, volume_run=volume_run)
    _unlink_our_image(artifacts)
    remove_created_mount_dir(artifacts.mount_point, artifacts.created_mount_dir)
    if artifacts.created_image_dir is not None:
        with contextlib.suppress(OSError):
            artifacts.created_image_dir.rmdir()


def _create_image(
    artifacts: _InitArtifacts, *, size: str, volume_name: str, passphrase: str, volume_run: VolumeRunner
) -> None:
    # Re-assert the reservation: the `lexists` in `_prepare_image_target` ran
    # before the prompts, and refusing here (rather than after a failed
    # create) keeps `created_image` false so rollback cannot touch the file.
    _refuse_occupied_image(artifacts.image)
    artifacts.created_image = True
    create_encrypted_image(artifacts.image, size=size, volume_name=volume_name, passphrase=passphrase, run=volume_run)
    artifacts.image_identity = _image_identity(artifacts.image)


def _create_and_record(
    artifacts: _InitArtifacts,
    *,
    config_path: Path,
    size: str,
    volume_name: str,
    mode: str,
    passphrase: str,
    mount_identity: PathIdentity | None,
    run: SubprocessRunner,
    volume_run: VolumeRunner,
    ismount: Callable[[str], bool],
) -> VerifiedHome:
    """Create the image, attach it, and record the mounted volume as the secure home."""
    try:
        _create_image(artifacts, size=size, volume_name=volume_name, passphrase=passphrase, volume_run=volume_run)
        recheck_mount_point(artifacts.mount_point, mount_identity)
        artifacts.attached = True
        artifacts.device_node = attach_image(
            artifacts.image, artifacts.mount_point, passphrase=passphrase, run=volume_run
        ).device_node
    except (SecureHomeVolumeError, ValueError) as exc:
        raise Refusal(error_message(exc)) from exc
    finally:
        # Best effort only: CPython cannot zeroize a str, so this just drops
        # our reference as early as possible rather than promising erasure.
        del passphrase

    try:
        verified = record_volume(
            artifacts.mount_point,
            config_path=config_path,
            run=run,
            ismount=ismount,
            mode=mode,
            backing=Backing(BACKING_DISK_IMAGE, artifacts.image),
        )
    except (SecureHomeVerificationError, SecureHomeConfigError, OSError) as exc:
        raise Refusal(error_message(exc)) from exc
    artifacts.recorded = True
    return verified


def _print_init_success(artifacts: _InitArtifacts, *, verified: VerifiedHome, mode: str) -> None:
    color = _term.should_color(sys.stdout)
    print(_term.heading("Secure home initialized.", enabled=color))
    print(f"  image       : {artifacts.image}")
    print(f"  mount point : {artifacts.mount_point}")
    print(f"  volume uuid : {verified.volume_uuid}")
    print(f"  secure home : {verified.home}")
    print(f"  mode        : {mode}")
    print(_term.hint("Next: hermes-mordred secure-home run -- hermes", enabled=color))
    if mode == MODE_STRICT:
        lock_hint = "Strict mode: lock it after every session with `hermes-mordred secure-home unmount`."
    else:
        lock_hint = "Lock it when done: hermes-mordred secure-home unmount"
    print(_term.hint(lock_hint, enabled=color))
    print(
        _term.hint(
            "note: your existing ~/.hermes was NOT migrated (Phase 3) — Hermes starts fresh inside the secure home.",
            enabled=color,
        )
    )


def _run_init(
    artifacts: _InitArtifacts,
    *,
    config_path: Path,
    prompt_io: PromptIO,
    size: str,
    volume_name: str,
    mode: str | None,
    run: SubprocessRunner,
    volume_run: VolumeRunner,
    ismount: Callable[[str], bool],
) -> int:
    """The ordered ``init`` steps. Any :class:`Refusal` is caught (and rolled back) by :func:`init`."""
    _prepare_image_target(artifacts)
    mount_state = prepare_mount_point(artifacts.mount_point, ismount)
    artifacts.created_mount_dir = mount_state.created
    chosen_mode = _resolve_mode(mode, prompt_io)
    passphrase = _collect_new_passphrase(prompt_io)
    _warn_if_filevault_off(run)
    verified = _create_and_record(
        artifacts,
        config_path=config_path,
        size=size,
        volume_name=volume_name,
        mode=chosen_mode,
        passphrase=passphrase,
        mount_identity=mount_state.identity,
        run=run,
        volume_run=volume_run,
        ismount=ismount,
    )
    del passphrase
    _print_init_success(artifacts, verified=verified, mode=chosen_mode)
    return 0


def init(
    *,
    config_path: Path,
    platform: str,
    prompt_io: PromptIO,
    image_path: Path | None = None,
    mount_point: Path | None = None,
    size: str = DEFAULT_SIZE,
    volume_name: str = DEFAULT_VOLUME_NAME,
    mode: str | None = None,
    force: bool = False,
    run: SubprocessRunner = DEFAULT_RUNNER,
    volume_run: VolumeRunner = DEFAULT_VOLUME_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
    home_dir: Path | None = None,
) -> int:
    """Create an encrypted disk image, attach it, and record it as the secure home.

    ``--force`` replaces an existing *config*; it never overwrites an existing
    image, and no failure path deletes an artifact this run did not create.
    The passphrase is collected interactively (twice) and never appears in
    ``argv``, the environment, or any output.
    """
    if platform != _DARWIN:
        _refuse_not_macos("init")
        return 1
    if force:
        _warn_replacing_config(config_path)
    else:
        refusal = _refuse_existing_config(config_path)
        if refusal is not None:
            return refusal

    home = home_dir if home_dir is not None else Path.home()
    artifacts = _InitArtifacts(
        image=_to_absolute(image_path if image_path is not None else default_image_path(home)),
        mount_point=_to_absolute(mount_point if mount_point is not None else default_mount_point(home)),
    )
    try:
        return _run_init(
            artifacts,
            config_path=config_path,
            prompt_io=prompt_io,
            size=size,
            volume_name=volume_name,
            mode=mode,
            run=run,
            volume_run=volume_run,
            ismount=ismount,
        )
    except Refusal as exc:
        _rollback_init(artifacts, volume_run=volume_run, ismount=ismount)
        _term.emit_error(exc.message)
        return 1
    except BaseException:
        # Ctrl-C during the slow create/attach, Ctrl-D at a prompt, or a
        # --non-interactive abort. An interrupt must not be the one path that
        # leaves this run's artifacts behind, so roll back and let
        # ``cli.dispatch`` map the exception to its usual exit code.
        _rollback_init(artifacts, volume_run=volume_run, ismount=ismount)
        raise


# -----------------------------------------------------------------------------
# MOUNT
# -----------------------------------------------------------------------------
@dataclass
class _MountAttempt:
    """What this ``mount`` run changed, so a failure can undo exactly that."""

    created_mount_dir: bool = False
    device_node: str | None = None


def _report_already_mounted(config: SecureHomeConfig, *, run: SubprocessRunner, ismount: Callable[[str], bool]) -> int:
    """Idempotent path: something is mounted there already, so only verify it — never touch it."""
    try:
        verified = verify_home(config, run=run, ismount=ismount)
    except SecureHomeVerificationError as exc:
        _term.emit_error(exc.message)
        return 1
    print("Secure home is already mounted and verified.")
    print(f"  secure home : {verified.home}")
    return 0


def _unlock_backing(
    config: SecureHomeConfig,
    backing: Backing,
    *,
    prompt_io: PromptIO,
    volume_run: VolumeRunner,
    mount_identity: PathIdentity | None,
    attempt: _MountAttempt,
) -> None:
    """Attach the image (or unlock the native volume) with a freshly prompted passphrase."""
    if backing.kind == BACKING_DISK_IMAGE:
        image, image_identity = require_image_file(backing.image_path)
    else:
        image, image_identity = None, None
    passphrase = prompt_io.ask_password("Secure-home volume passphrase")
    try:
        if not passphrase:
            raise Refusal("Passphrase must not be empty — nothing was mounted.")
        _refuse_untypable_passphrase(passphrase, "nothing was mounted")
        # Re-assert both paths here, after the prompt: this is the last
        # instant before the operator's passphrase leaves the process.
        recheck_mount_point(config.mount_point, mount_identity)
        try:
            if image is not None and image_identity is not None:
                recheck_image_identity(image, image_identity)
                attempt.device_node = attach_image(
                    image, config.mount_point, passphrase=passphrase, run=volume_run
                ).device_node
            else:
                unlock_native_volume(config.volume_uuid, config.mount_point, passphrase=passphrase, run=volume_run)
        except (SecureHomeVolumeError, ValueError) as exc:
            raise Refusal(error_message(exc)) from exc
    finally:
        del passphrase  # best effort; see the module docstring


def _relock_note(config: SecureHomeConfig, backing: Backing, *, relocked: bool) -> str:
    """Say what actually happened to the volume — never claim a put-back that failed."""
    if backing.kind == BACKING_DISK_IMAGE:
        done, verb, manual = "detached", "detach", f"hdiutil detach {config.mount_point}"
    else:
        done, verb, manual = "locked", "lock", f"diskutil apfs lockVolume {config.volume_uuid}"
    if relocked:
        return f" The volume was {done} again."
    return f" The volume could NOT be {done} again — {verb} it yourself: {manual}"


def _mount_configured(
    config: SecureHomeConfig,
    *,
    prompt_io: PromptIO,
    run: SubprocessRunner,
    volume_run: VolumeRunner,
    ismount: Callable[[str], bool],
) -> int:
    if ismount(str(config.mount_point)):
        return _report_already_mounted(config, run=run, ismount=ismount)

    attempt = _MountAttempt()
    try:
        backing = require_backing(config)
        mount_state = prepare_mount_point(config.mount_point, ismount)
        attempt.created_mount_dir = mount_state.created
        _unlock_backing(
            config,
            backing,
            prompt_io=prompt_io,
            volume_run=volume_run,
            mount_identity=mount_state.identity,
            attempt=attempt,
        )
    except Refusal as exc:
        remove_created_mount_dir(config.mount_point, attempt.created_mount_dir)
        _term.emit_error(exc.message)
        return 1
    except BaseException:
        # Ctrl-C / Ctrl-D at the passphrase prompt, or a --non-interactive
        # abort: the empty directory we just made is ours to clean up.
        remove_created_mount_dir(config.mount_point, attempt.created_mount_dir)
        raise

    try:
        verified = verify_home(config, run=run, ismount=ismount)
    except SecureHomeVerificationError as exc:
        target = Path(attempt.device_node) if attempt.device_node else None
        relocked = relock_after_failed_verification(config, backing, volume_run=volume_run, target=target)
        remove_created_mount_dir(config.mount_point, attempt.created_mount_dir)
        _term.emit_error(f"{exc.message}{_relock_note(config, backing, relocked=relocked)}")
        return 1

    print("Secure home mounted.")
    print(f"  secure home : {verified.home}")
    print(_term.hint("Next: hermes-mordred secure-home run -- hermes", enabled=_term.should_color(sys.stdout)))
    return 0


def mount(
    *,
    config_path: Path,
    platform: str,
    prompt_io: PromptIO,
    run: SubprocessRunner = DEFAULT_RUNNER,
    volume_run: VolumeRunner = DEFAULT_VOLUME_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
) -> int:
    """Unlock the configured secure home, then re-verify it end to end.

    Idempotent: an already-mounted secure home is verified and reported
    without prompting or touching the volume. A volume that attaches but then
    fails verification is put back — and the message says so only when the
    put-back actually worked.
    """
    if platform != _DARWIN:
        _refuse_not_macos("mount")
        return 1
    try:
        config = load_required_config(config_path)
    except Refusal as exc:
        _term.emit_error(exc.message)
        return 1
    return _mount_configured(config, prompt_io=prompt_io, run=run, volume_run=volume_run, ismount=ismount)


# -----------------------------------------------------------------------------
# UNMOUNT (policy lives in ._secure_home_unmount)
# -----------------------------------------------------------------------------
def unmount(
    *,
    config_path: Path,
    platform: str,
    force: bool = False,
    run: SubprocessRunner = DEFAULT_RUNNER,
    volume_run: VolumeRunner = DEFAULT_VOLUME_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
) -> int:
    """Lock the configured secure home, refusing to eject anything that is not it.

    Volume identity is confirmed *before* the detach, so a different volume
    mounted at the configured path is refused. When nothing is mounted at the
    configured path the volume is *probed* rather than assumed locked — an
    image auto-mounted under ``/Volumes`` is detached and reported. A busy
    volume is reported (with the ``--force`` escape hatch named) rather than
    force-ejected by default.
    """
    if platform != _DARWIN:
        _refuse_not_macos("unmount")
        return 1
    return unmount_with_config(config_path=config_path, force=force, run=run, volume_run=volume_run, ismount=ismount)


# -----------------------------------------------------------------------------
# argparse handlers — resolve production defaults, then delegate.
# -----------------------------------------------------------------------------
def _optional_path(args: argparse.Namespace, attribute: str) -> Path | None:
    value = getattr(args, attribute, None)
    return Path(value) if value else None


def cli_init(args: argparse.Namespace) -> int:
    """argparse handler for ``secure-home init [--image ...] [--mount-point ...] [...]``."""
    return init(
        config_path=resolve_config_path(),
        platform=sys.platform,
        prompt_io=PromptToolkitIO(),
        image_path=_optional_path(args, "image"),
        mount_point=_optional_path(args, "mount_point"),
        size=getattr(args, "size", None) or DEFAULT_SIZE,
        volume_name=getattr(args, "volname", None) or DEFAULT_VOLUME_NAME,
        mode=getattr(args, "mode", None),
        force=bool(getattr(args, "force", False)),
    )


def cli_mount(args: argparse.Namespace) -> int:
    """argparse handler for ``secure-home mount``."""
    return mount(config_path=resolve_config_path(), platform=sys.platform, prompt_io=PromptToolkitIO())


def cli_unmount(args: argparse.Namespace) -> int:
    """argparse handler for ``secure-home unmount [--force]``."""
    return unmount(
        config_path=resolve_config_path(),
        platform=sys.platform,
        force=bool(getattr(args, "force", False)),
    )
