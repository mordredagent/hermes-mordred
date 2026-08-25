"""Shared refusal type + preparation steps for the secure-home volume ceremonies.

``secure_home_lifecycle_cli`` (``init``/``mount``) and ``_secure_home_unmount``
(``unmount``) both have to answer the same questions before they touch a
volume — is this config usable, is this mount point safe to mount onto, is
this image still the file the config named — and both have to turn a "no" into
one printed line and exit 1. Keeping those answers here means the two
ceremonies cannot drift into judging the same situation differently, and it
keeps each ceremony module small enough to read end to end.

**Refusals are an exception, not a return code.** Every step raises
:class:`Refusal`; each entry point catches it in exactly one place, rolls back
whatever that ceremony created, prints the message and returns 1. Threading a
``bool``/``int`` back through eight nested helpers instead would put a
"did this fail?" branch at every call site, which is precisely where a
fail-open bug hides.

**Identity, not paths.** ``prepare_mount_point`` and ``require_image_file``
return the ``(st_dev, st_ino)`` of what they approved, and
:func:`recheck_mount_point` / :func:`recheck_image_identity` re-assert it
immediately before the passphrase is handed to a tool. A path checked at
prompt time and used minutes later (human-speed prompts sit in the middle) is
a path an attacker has had time to swap for a symlink into something they can
read; comparing inode identity closes that window in the only place it can be
closed cheaply.
"""

from __future__ import annotations

import contextlib
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Final

from ._secure_home_paths import Backing, SecureHomeConfig
from ._secure_home_probe import SecureHomeVerificationError, _refuse_symlink_component
from .secure_home_cli import _load_config_safe

__all__ = [
    "DIR_MODE",
    "NOT_CONFIGURED_REFUSAL",
    "UNKNOWN_BACKING_REFUSAL",
    "MountPointState",
    "PathIdentity",
    "Refusal",
    "error_message",
    "load_required_config",
    "lstat_or_none",
    "prepare_mount_point",
    "recheck_image_identity",
    "recheck_mount_point",
    "refuse_symlinked_path",
    "remove_created_mount_dir",
    "require_backing",
    "require_image_file",
]

DIR_MODE: Final[int] = 0o700

#: ``(st_dev, st_ino)`` — the pair that says "the same file", surviving a
#: rename and unaffected by a path being re-pointed at something else.
PathIdentity = tuple[int, int]

UNKNOWN_BACKING_REFUSAL: Final[str] = (
    "this config does not record how the volume is provided. While the volume is mounted, run "
    "'hermes-mordred secure-home adopt --force <mountpoint>' to record it, then retry."
)

NOT_CONFIGURED_REFUSAL: Final[str] = (
    "Secure home is not configured. Run 'hermes-mordred secure-home init' (or adopt) first."
)


class Refusal(Exception):
    """An operator-facing refusal, printed once by the ceremony that catches it."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def error_message(exc: BaseException) -> str:
    """The operator-facing text of an error — never a repr, never a traceback."""
    message = getattr(exc, "message", None)
    return message if isinstance(message, str) else str(exc)


def _identity(metadata: os.stat_result) -> PathIdentity:
    return (metadata.st_dev, metadata.st_ino)


def refuse_symlinked_path(path: Path) -> None:
    try:
        _refuse_symlink_component(path)
    except SecureHomeVerificationError as exc:
        raise Refusal(exc.message) from exc


def lstat_or_none(path: Path) -> os.stat_result | None:
    """``lstat`` without following the final symlink; ``None`` when absent."""
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise Refusal(f"could not inspect {path}: {exc}") from exc


# -----------------------------------------------------------------------------
# Mount point
# -----------------------------------------------------------------------------
class MountPointState:
    """What :func:`prepare_mount_point` approved: whether we made it, and which directory it was."""

    __slots__ = ("created", "identity")

    def __init__(self, *, created: bool, identity: PathIdentity | None) -> None:
        self.created = created
        self.identity = identity


def _create_mount_dir(mount_point: Path) -> None:
    try:
        mount_point.mkdir(mode=DIR_MODE, parents=True)
        os.chmod(mount_point, DIR_MODE)  # umask defense: mkdir's mode alone can be widened
    except OSError as exc:
        raise Refusal(f"could not create the mount point {mount_point}: {exc}") from exc


def _refuse_unusable_mount_dir(mount_point: Path, metadata: os.stat_result, ismount: Callable[[str], bool]) -> None:
    """An existing mount point must be an empty, unmounted directory we can safely mount onto."""
    if not stat.S_ISDIR(metadata.st_mode):
        raise Refusal(f"{mount_point} exists and is not a directory; pick another mount point. Nothing was created.")
    if ismount(str(mount_point)):
        raise Refusal(
            f"something is already mounted at {mount_point}; unmount it first or pick another mount point. "
            "Nothing was created."
        )
    try:
        occupied = any(mount_point.iterdir())
    except OSError as exc:
        raise Refusal(f"could not inspect the mount point {mount_point}: {exc}") from exc
    if occupied:
        raise Refusal(
            f"the mount point {mount_point} is not empty; mounting onto it would hide its contents. "
            "Empty it yourself or pick another mount point. Nothing was created."
        )


def prepare_mount_point(mount_point: Path, ismount: Callable[[str], bool]) -> MountPointState:
    """Ensure *mount_point* is a safe, empty, unmounted directory, creating it if absent."""
    refuse_symlinked_path(mount_point)
    metadata = lstat_or_none(mount_point)
    if metadata is None:
        _create_mount_dir(mount_point)
        created = True
        metadata = lstat_or_none(mount_point)
    else:
        _refuse_unusable_mount_dir(mount_point, metadata, ismount)
        created = False
    return MountPointState(created=created, identity=_identity(metadata) if metadata is not None else None)


def recheck_mount_point(mount_point: Path, identity: PathIdentity | None) -> None:
    """Re-assert that the approved directory is still that same directory.

    Called immediately before the attach. ``posixpath.ismount`` answers
    ``False`` for a symlink, so a mount point swapped for a symlink between
    approval and attach would mount the volume through the attacker's target
    *and* make the rollback's ``ismount`` check skip the detach — the volume
    would stay live with nothing tracking it.
    """
    if identity is None:
        return
    metadata = lstat_or_none(mount_point)
    if metadata is None or not stat.S_ISDIR(metadata.st_mode) or _identity(metadata) != identity:
        raise Refusal(
            f"the mount point {mount_point} changed while we were preparing to mount "
            "(it is no longer the directory that was checked); nothing was mounted."
        )


def remove_created_mount_dir(mount_point: Path, created: bool) -> None:
    """Roll back a mount directory *this run* created; never one that already existed."""
    if created:
        with contextlib.suppress(OSError):
            mount_point.rmdir()  # rmdir only removes an empty directory


# -----------------------------------------------------------------------------
# Config / backing / image
# -----------------------------------------------------------------------------
def load_required_config(config_path: Path) -> SecureHomeConfig:
    config, load_error = _load_config_safe(config_path)
    if load_error is not None:
        raise Refusal(load_error)
    if config is None:
        raise Refusal(NOT_CONFIGURED_REFUSAL)
    return config


def require_backing(config: SecureHomeConfig) -> Backing:
    if config.backing is None:
        raise Refusal(UNKNOWN_BACKING_REFUSAL)
    return config.backing


def require_image_file(image_path: Path | None) -> tuple[Path, PathIdentity]:
    """The recorded image must still be there and still be a plain file.

    Returns its ``(st_dev, st_ino)`` so the caller can re-assert the same file
    after the passphrase prompt (see :func:`recheck_image_identity`). A
    symlink is refused rather than followed: the config points at a path we
    are about to hand to ``hdiutil attach`` together with the operator's
    passphrase, and a swapped link would redirect that to someone else's
    image — which would then be unlocked with, and thereby test, our
    passphrase.
    """
    if image_path is None:
        raise Refusal(
            "this config records a disk-image backing but no image path; while the volume is mounted, run "
            "'hermes-mordred secure-home adopt --force <mountpoint>' to record it, then retry."
        )
    metadata = lstat_or_none(image_path)
    if metadata is None:
        raise Refusal(f"the secure-home disk image no longer exists: {image_path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise Refusal(f"the secure-home disk image is not a regular file (refusing a symlink or device): {image_path}")
    return image_path, _identity(metadata)


def recheck_image_identity(image_path: Path, identity: PathIdentity) -> None:
    """Re-assert the approved image immediately before the passphrase reaches ``hdiutil``."""
    metadata = lstat_or_none(image_path)
    if metadata is None or not stat.S_ISREG(metadata.st_mode) or _identity(metadata) != identity:
        raise Refusal(
            f"the secure-home disk image at {image_path} changed while we were preparing to mount "
            "(it is no longer the file that was checked); nothing was mounted."
        )
