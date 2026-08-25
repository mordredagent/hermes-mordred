"""Locking a configured secure home — ``hermes-mordred secure-home unmount``.

Split out of :mod:`.secure_home_lifecycle_cli` to keep both modules readable
(and under the repository's size guideline). This half owns everything about
*ending* a session: the lock/detach policy, the busy/``--force`` rules, and
the identity check that must pass before anything is ejected. ``init`` and
``mount`` also lock a volume — after a failed verification — so
:func:`lock_backing` and :func:`relock_after_failed_verification` live here
and are imported there rather than duplicated.

**Never eject a volume we did not identify.** :func:`verify_mounted_identity`
(chain steps 1-4 only) runs *before* any detach: something else mounted at the
configured path is refused, not unmounted. The acceptance steps are
deliberately skipped — refusing to lock a volume because it is mounted
``noowners`` would strand it unlockable, which is the opposite of safe.

**Never report "locked" without checking.** ``os.path.ismount(<configured
mount point>)`` answers "is it here", not "is it live". An image attached by
Finder, or by a bare ``hdiutil attach`` with no ``-mountpoint``, auto-mounts
under ``/Volumes/<volname>``; a native volume can be unlocked to any path. So
when nothing is at the configured path this module *probes* — ``hdiutil
info`` for the image, ``diskutil info <uuid>`` for the native volume — and
locks what it finds, naming where it found it. A probe that fails is a
refusal, never an assumed "not attached": printing "Secure home locked" over a
live volume is the precise false assurance secure-home exists to prevent.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from . import _term
from ._secure_home_ceremony import (
    Refusal,
    load_required_config,
    require_backing,
)
from ._secure_home_paths import BACKING_APFS_VOLUME, BACKING_DISK_IMAGE, Backing, SecureHomeConfig
from ._secure_home_probe import (
    UUID_MISMATCH,
    SecureHomeProbeError,
    SecureHomeVerificationError,
    SubprocessRunner,
    attached_image_device,
    native_volume_state,
    verify_mounted_identity,
)
from ._secure_home_volume import (
    VOLUME_BUSY,
    SecureHomeVolumeError,
    VolumeRunner,
    detach,
    force_unmount_native,
    lock_native_volume,
)

__all__ = ["lock_backing", "relock_after_failed_verification", "unmount_configured", "unmount_with_config"]

_BUSY_ADVICE = " Stop Hermes/Gateway processes that use the secure home and retry, or pass --force."


# -----------------------------------------------------------------------------
# The lock primitive, shared with init/mount's failed-verification rollback
# -----------------------------------------------------------------------------
def lock_backing(
    config: SecureHomeConfig,
    backing: Backing,
    *,
    force: bool,
    volume_run: VolumeRunner,
    target: Path | None = None,
) -> None:
    """Detach the image, or lock the native volume (force-unmounting first when told to).

    *target* overrides the path acted on: the configured mount point by
    default, but a ``/dev/diskN`` node (for an image attached elsewhere) or
    the volume's actual mount point when the probe found it somewhere we did
    not put it.
    """
    where = target if target is not None else config.mount_point
    if backing.kind == BACKING_DISK_IMAGE:
        detach(where, force=force, run=volume_run)
        return
    try:
        lock_native_volume(config.volume_uuid, run=volume_run)
    except SecureHomeVolumeError as exc:
        if exc.code != VOLUME_BUSY or not force:
            raise
        force_unmount_native(where, run=volume_run)
        try:
            lock_native_volume(config.volume_uuid, run=volume_run)
        except SecureHomeVolumeError as retry_exc:
            # The volume is at least unmounted; report and let the caller's
            # post-check decide, rather than claiming a failure that would
            # hide the progress actually made.
            _term.emit_warn(f"the volume was force-unmounted but could not be locked: {retry_exc.message}")


def relock_after_failed_verification(
    config: SecureHomeConfig, backing: Backing, *, volume_run: VolumeRunner, target: Path | None = None
) -> bool:
    """Lock a volume we just attached but cannot verify. ``False`` when that failed.

    The caller must not claim the volume was put back if it wasn't — an
    operator told "the volume was detached again" stops looking, and a
    verification failure is exactly when an un-detached volume matters most.
    """
    try:
        lock_backing(config, backing, force=False, volume_run=volume_run, target=target)
    except SecureHomeVolumeError as exc:
        _term.emit_warn(f"could not lock the volume again after the failed verification: {exc.message}")
        return False
    return True


# -----------------------------------------------------------------------------
# unmount
# -----------------------------------------------------------------------------
def _verify_unmount_target(config: SecureHomeConfig, *, run: SubprocessRunner, ismount: Callable[[str], bool]) -> None:
    """Identity only — an acceptance concern must never strand a volume as un-lockable."""
    try:
        verify_mounted_identity(config, run=run, ismount=ismount)
    except SecureHomeVerificationError as exc:
        if exc.code == UUID_MISMATCH:
            raise Refusal(
                f"{exc.message} Refusing to unmount a volume that is not the configured secure home."
            ) from exc
        raise Refusal(exc.message) from exc


def _lock_for_unmount(
    config: SecureHomeConfig,
    backing: Backing,
    *,
    force: bool,
    volume_run: VolumeRunner,
    target: Path | None = None,
) -> None:
    try:
        lock_backing(config, backing, force=force, volume_run=volume_run, target=target)
    except SecureHomeVolumeError as exc:
        if exc.code == VOLUME_BUSY and not force:
            raise Refusal(f"{exc.message}{_BUSY_ADVICE}") from exc
        raise Refusal(exc.message) from exc


def _lock_image_elsewhere(
    config: SecureHomeConfig, backing: Backing, *, force: bool, run: SubprocessRunner, volume_run: VolumeRunner
) -> int:
    """Nothing at the configured path — but is the image attached somewhere else?"""
    image = backing.image_path
    if image is None:
        raise Refusal(
            f"nothing is mounted at {config.mount_point}, and this config records no image path, so whether "
            "the volume is attached elsewhere cannot be checked. Re-run 'secure-home adopt --force <mountpoint>' "
            "while it is mounted to record it."
        )
    try:
        attached = attached_image_device(image, run=run)
    except SecureHomeProbeError as exc:
        raise Refusal(f"Could not determine whether {image} is still attached: {exc}") from exc
    if attached is None:
        print(f"Secure home is locked (nothing mounted at {config.mount_point}; the image is not attached).")
        return 0
    _lock_for_unmount(config, backing, force=force, volume_run=volume_run, target=Path(attached.device_node))
    where = ", ".join(attached.mount_points) if attached.mount_points else attached.device_node
    print(f"Secure home locked (it was attached at {where} rather than {config.mount_point}).")
    return 0


def _lock_native_elsewhere(
    config: SecureHomeConfig, *, force: bool, run: SubprocessRunner, volume_run: VolumeRunner
) -> int:
    """Nothing at the configured path — but is the native volume unlocked somewhere else?"""
    try:
        locked, mount_point = native_volume_state(config.volume_uuid, run=run)
    except SecureHomeProbeError as exc:
        raise Refusal(f"Could not determine whether the secure volume is unlocked: {exc}") from exc
    if locked is not False:
        state = "locked" if locked else "not attached"
        print(f"Secure home is locked (nothing mounted at {config.mount_point}; the volume is {state}).")
        return 0
    target = Path(mount_point) if mount_point else None
    _lock_for_unmount(config, Backing(BACKING_APFS_VOLUME), force=force, volume_run=volume_run, target=target)
    print(f"Secure home locked (it was attached at {mount_point or 'another path'} rather than {config.mount_point}).")
    return 0


def _lock_elsewhere(config: SecureHomeConfig, *, force: bool, run: SubprocessRunner, volume_run: VolumeRunner) -> int:
    if config.backing is None:
        # We cannot probe without knowing which subsystem owns the volume, so
        # say exactly that instead of implying we confirmed it is locked.
        print(
            f"Secure home is locked (nothing mounted at {config.mount_point}; this config does not record the "
            "backing, so whether the volume is attached elsewhere was not checked)."
        )
        return 0
    if config.backing.kind == BACKING_DISK_IMAGE:
        return _lock_image_elsewhere(config, config.backing, force=force, run=run, volume_run=volume_run)
    return _lock_native_elsewhere(config, force=force, run=run, volume_run=volume_run)


def unmount_configured(
    config: SecureHomeConfig,
    *,
    force: bool,
    run: SubprocessRunner,
    volume_run: VolumeRunner,
    ismount: Callable[[str], bool],
) -> int:
    """The body of ``unmount`` once a config is loaded: probe, verify, lock, re-check."""
    try:
        if not ismount(str(config.mount_point)):
            return _lock_elsewhere(config, force=force, run=run, volume_run=volume_run)
        _verify_unmount_target(config, run=run, ismount=ismount)
        backing = require_backing(config)
        _lock_for_unmount(config, backing, force=force, volume_run=volume_run)
    except Refusal as exc:
        _term.emit_error(exc.message)
        return 1
    if ismount(str(config.mount_point)):
        _term.emit_error(f"secure home is still mounted at {config.mount_point} after the unmount attempt.")
        return 1
    print("Secure home locked.")
    return 0


def unmount_with_config(
    *,
    config_path: Path,
    force: bool,
    run: SubprocessRunner,
    volume_run: VolumeRunner,
    ismount: Callable[[str], bool],
) -> int:
    """Load the config, then delegate — the body of ``secure-home unmount`` after the platform gate."""
    try:
        config = load_required_config(config_path)
    except Refusal as exc:
        _term.emit_error(exc.message)
        return 1
    return unmount_configured(config, force=force, run=run, volume_run=volume_run, ismount=ismount)
