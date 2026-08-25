"""Read-only macOS probes + the fail-closed identity chain for secure-home.

``hermes-mordred secure-home`` runs Hermes with ``HERMES_HOME`` pointed at a
volume the *operator* mounted, not one we created or own. Before trusting
that mount for anything holding secrets, we have to independently confirm it
is actually the volume the config describes — not merely "something is
mounted at this path" (an attacker, or just a stale leftover mount, could put
anything there). :func:`verify_home` is that confirmation: a strict,
ordered chain of checks that all fail closed, backed by ``fdesetup`` (whole-
disk FileVault, informational only), ``diskutil`` (per-volume identity —
UUID, filesystem, encryption, ownership, mount state), and ``hdiutil``
(image-layer encryption for disk-image-backed volumes).

Encryption is deliberately judged from two distinct signals, because the
volume-level ``diskutil`` keys alone are wrong in both directions on real
macOS: FileVault boot volumes report ``Encryption``/``FileVault`` true (which
would falsely "verify" a home that is merely on the auto-unlocked boot disk),
while ``hdiutil``-created encrypted disk images report every volume-level
encryption key false (the encryption lives at the *image* layer). So the
chain accepts only ``EncryptionThisVolumeProper`` (a natively encrypted APFS
volume) or a backing disk image that ``hdiutil info`` reports as encrypted —
and refuses boot/system volumes outright, since relocating ``HERMES_HOME``
there can never provide the independent second key layer this feature
promises.

Every subprocess call is factored through an injectable
:class:`SubprocessRunner` — mirroring
``mordred_hermes.network.paths.vpn.SubprocessRunner`` — so unit tests never
invoke a real ``fdesetup``/``diskutil``/``hdiutil`` and never depend on an
actual mounted volume. The default runner also pins a minimal
``PATH``/``LC_ALL`` env: these are read-only system tools, not user
configuration, and a hijacked ``PATH`` entry shadowing ``diskutil`` must not
be able to lie to this chain.
"""

from __future__ import annotations

import contextlib
import enum
import os
import plistlib
import re
import stat
import subprocess
import uuid as uuid_module
import xml.parsers.expat
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any, Final, Protocol

from ._secure_home_paths import SecureHomeConfig

__all__ = [
    "BOOT_VOLUME",
    "DEFAULT_RUNNER",
    "HOME_MISSING",
    "NOT_APFS",
    "NOT_ENCRYPTED",
    "NOT_MOUNTED",
    "OWNERSHIP_DISABLED",
    "PROBE_FAILED",
    "UNSAFE_HOME",
    "UUID_MISMATCH",
    "AttachedImage",
    "FileVaultState",
    "SecureHomeProbeError",
    "SecureHomeVerificationError",
    "SubprocessRunner",
    "VerifiedHome",
    "VolumeInfo",
    "attached_image_device",
    "backing_image_path",
    "ensure_volume_acceptable",
    "filevault_status",
    "inspect_mounted_volume",
    "native_volume_state",
    "verify_home",
    "verify_mounted_identity",
    "volume_info",
]

_PINNED_ENV: Final[dict[str, str]] = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_FILEVAULT_STATUS_TIMEOUT: Final[float] = 10.0
_VOLUME_INFO_TIMEOUT: Final[float] = 15.0
_HDIUTIL_INFO_TIMEOUT: Final[float] = 15.0
_STDERR_TRIM_LIMIT: Final[int] = 200

# Truncated-but-well-headed plist bodies raise ExpatError, which is NOT a
# ValueError — omitting it lets a flaky `diskutil` crash the fail-closed chain
# with a raw traceback instead of a refusal.
_PLIST_PARSE_ERRORS: Final = (plistlib.InvalidFileException, ValueError, xml.parsers.expat.ExpatError)

_geteuid = getattr(os, "geteuid", None)


class SubprocessRunner(Protocol):
    """The injectable command runner contract for the secure-home probes.

    Mirrors ``network.paths.vpn.SubprocessRunner``'s injection pattern, kept
    intentionally narrower: every call site here is read-only and always
    passes ``timeout=``, so there is no ``check``/``capture_output``/``text``
    surface to negotiate — those are fixed in :func:`_default_runner`.
    """

    def __call__(self, argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]: ...


def _default_runner(argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    """Production default: a real ``subprocess.run`` with a pinned minimal env."""
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=_PINNED_ENV,
    )


DEFAULT_RUNNER: Final[SubprocessRunner] = _default_runner


class FileVaultState(enum.Enum):
    """Whole-disk FileVault state, as reported by ``fdesetup status``."""

    ON = "on"
    OFF = "off"
    UNKNOWN = "unknown"


def filevault_status(*, run: SubprocessRunner = DEFAULT_RUNNER) -> FileVaultState:
    """Report whole-disk FileVault state. Informational only — never raises.

    ``UNKNOWN`` covers every failure mode (non-zero exit, unparsable output,
    a missing ``fdesetup`` binary, a timeout): this is advisory context for
    the CLI, not a security gate, so callers must not treat ``UNKNOWN`` as
    either ON or OFF.
    """
    try:
        result = run(("fdesetup", "status"), timeout=_FILEVAULT_STATUS_TIMEOUT)
    except (OSError, subprocess.SubprocessError, ValueError):
        return FileVaultState.UNKNOWN
    if result.returncode != 0:
        return FileVaultState.UNKNOWN
    stdout = result.stdout or ""
    if "FileVault is On" in stdout:
        return FileVaultState.ON
    if "FileVault is Off" in stdout:
        return FileVaultState.OFF
    return FileVaultState.UNKNOWN


class SecureHomeProbeError(Exception):
    """Raised when ``diskutil``/``hdiutil`` cannot be invoked or their output cannot be parsed."""


@dataclass(frozen=True)
class VolumeInfo:
    """Defensively-extracted fields from ``diskutil info -plist``.

    Every field is ``None`` when ``diskutil`` didn't report it — a missing
    key is not the same as a known-false value, and callers (notably
    :func:`verify_home`) must fail closed on the distinction rather than
    guess.

    ``encryption_this_volume_proper`` is the only volume-level key that means
    "this APFS volume itself is encrypted with its own key"; the older
    ``Encrypted``/``Encryption``/``FileVault`` keys are FileVault/inherited
    signals and are deliberately not consulted (see module docstring).
    ``ownership_enabled`` mirrors ``GlobalPermissionsEnabled`` — when macOS
    mounts a volume ``noowners`` (the ``hdiutil attach`` default), every user
    is treated as the owner and on-disk permissions protect nothing.
    """

    volume_uuid: str | None
    filesystem: str | None
    mount_point: str | None
    device_node: str | None
    encryption_this_volume_proper: bool | None
    ownership_enabled: bool | None


def _invoke_plist_tool(argv: tuple[str, ...], *, run: SubprocessRunner, timeout: float) -> CompletedProcess[str]:
    """Run a plist-emitting tool, turning an invocation failure into :class:`SecureHomeProbeError`.

    Split out from :func:`_run_plist_tool` because a *non-zero exit* is not
    always a failure: ``diskutil info <uuid>`` exits non-zero to say "no such
    volume", which :func:`native_volume_state` must report as an answer rather
    than raise on.
    """
    try:
        return run(argv, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecureHomeProbeError(f"{' '.join(argv)!r} failed or timed out: {exc}") from exc


def _parse_plist_output(argv: tuple[str, ...], stdout: str) -> dict[str, Any]:
    try:
        parsed = plistlib.loads(stdout.encode())
    except _PLIST_PARSE_ERRORS as exc:
        raise SecureHomeProbeError(f"{' '.join(argv)!r} produced unparsable plist output: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SecureHomeProbeError(f"{' '.join(argv)!r} plist output is not a dictionary")
    return parsed


def _run_plist_tool(argv: tuple[str, ...], *, run: SubprocessRunner, timeout: float) -> dict[str, Any]:
    """Invoke a plist-emitting system tool, failing closed into :class:`SecureHomeProbeError`."""
    result = _invoke_plist_tool(argv, run=run, timeout=timeout)
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        raise SecureHomeProbeError(f"{' '.join(argv)!r} failed (rc={result.returncode}): {detail!r}")
    return _parse_plist_output(argv, result.stdout or "")


def volume_info(mount_point: Path, *, run: SubprocessRunner = DEFAULT_RUNNER) -> VolumeInfo:
    """Probe ``diskutil info -plist <mount_point>`` for the volume's identity.

    Raises :class:`SecureHomeProbeError` on invocation failure, a non-zero
    exit, or unparsable plist output — never returns a half-populated
    :class:`VolumeInfo` for those cases, so a caller can't mistake "diskutil
    failed" for "diskutil reported no UUID".
    """
    plist = _run_plist_tool(("diskutil", "info", "-plist", str(mount_point)), run=run, timeout=_VOLUME_INFO_TIMEOUT)
    return _parse_volume_info(plist)


def _trim(text: str, limit: int = _STDERR_TRIM_LIMIT) -> str:
    stripped = text.strip()
    return stripped if len(stripped) <= limit else stripped[:limit]


def _parse_str(plist: dict[str, Any], key: str) -> str | None:
    value = plist.get(key)
    return value if isinstance(value, str) else None


def _parse_bool(plist: dict[str, Any], key: str) -> bool | None:
    value = plist.get(key)
    return value if isinstance(value, bool) else None


def _parse_volume_info(plist: dict[str, Any]) -> VolumeInfo:
    filesystem = _parse_str(plist, "FilesystemType") or _parse_str(plist, "FilesystemName")
    return VolumeInfo(
        volume_uuid=_parse_str(plist, "VolumeUUID"),
        filesystem=filesystem,
        mount_point=_parse_str(plist, "MountPoint"),
        device_node=_parse_str(plist, "DeviceNode"),
        encryption_this_volume_proper=_parse_bool(plist, "EncryptionThisVolumeProper"),
        ownership_enabled=_parse_bool(plist, "GlobalPermissionsEnabled"),
    )


def _whole_disk(device_node: str) -> str | None:
    """``/dev/disk9s1`` → ``/dev/disk9`` (the whole-disk node ``hdiutil`` lists)."""
    match = re.match(r"^(/dev/disk\d+)", device_node)
    return match.group(1) if match else None


def _find_backing_image(device_node: str, *, run: SubprocessRunner) -> dict[str, Any] | None:
    """Return the attached ``hdiutil info -plist`` image dict backing *device_node*, or ``None``.

    Shared by :func:`_image_backed_encrypted` and :func:`backing_image_path`
    so "which image owns this device" is matched exactly once — an exact
    ``dev-entry`` match, or a match on the image's whole-disk node when
    *device_node* names one of its partitions. Raises
    :class:`SecureHomeProbeError` when ``hdiutil`` itself fails.
    """
    plist = _run_plist_tool(("hdiutil", "info", "-plist"), run=run, timeout=_HDIUTIL_INFO_TIMEOUT)
    images = plist.get("images")
    if not isinstance(images, list):
        return None
    whole_disk = _whole_disk(device_node)
    for image in images:
        if not isinstance(image, dict):
            continue
        entities = image.get("system-entities")
        if not isinstance(entities, list):
            continue
        dev_entries = {entity.get("dev-entry") for entity in entities if isinstance(entity, dict)}
        if device_node in dev_entries or (whole_disk is not None and whole_disk in dev_entries):
            return image
    return None


def _image_backed_encrypted(device_node: str, *, run: SubprocessRunner) -> bool | None:
    """Whether the attached disk image backing *device_node* is encrypted.

    Returns ``None`` when no attached image owns the device (the volume is
    not image-backed at all); ``False`` when an image owns it but does not
    report ``image-encrypted`` true — an image found without the flag is
    treated as unencrypted, never as unknown. Raises
    :class:`SecureHomeProbeError` when ``hdiutil`` itself fails.
    """
    image = _find_backing_image(device_node, run=run)
    if image is None:
        return None
    return _parse_bool(image, "image-encrypted") is True


def backing_image_path(device_node: str, *, run: SubprocessRunner = DEFAULT_RUNNER) -> Path | None:
    """Path of the attached disk image backing *device_node*.

    ``None`` when the volume is not image-backed at all, or when a matching
    image is found but its ``image-path`` key is absent or not a string —
    both are "we can't name the file", never a guess. Raises
    :class:`SecureHomeProbeError` when ``hdiutil`` fails (propagates from
    :func:`_run_plist_tool` via :func:`_find_backing_image`).
    """
    image = _find_backing_image(device_node, run=run)
    if image is None:
        return None
    image_path = _parse_str(image, "image-path")
    return Path(image_path) if image_path is not None else None


@dataclass(frozen=True)
class AttachedImage:
    """An attached disk image located by scanning ``hdiutil info -plist``.

    ``device_node`` is the *whole-disk* node (``/dev/disk9``), which is what
    ``hdiutil detach`` wants when the image is not mounted where we expected —
    detaching by mount point cannot work if there is no mount point of ours.
    ``mount_points`` is whatever the image is actually mounted at right now
    (possibly empty: attached but not mounted), and exists so the CLI can tell
    the operator *where* it found the volume instead of silently acting on a
    path they never mentioned.
    """

    device_node: str
    mount_points: tuple[str, ...]


def _path_aliases(value: str) -> frozenset[str]:
    """The spellings of *value* that should be considered the same file.

    ``hdiutil`` echoes the path it was given, so an image attached as
    ``/tmp/x.sparseimage`` and a config recording
    ``/private/tmp/x.sparseimage`` name one file under two names. Comparing
    the alias *sets* (rather than resolving only one side) also matches when
    the file has since been deleted and ``realpath`` can no longer follow it.
    """
    aliases = {value, os.path.normpath(value)}
    with contextlib.suppress(OSError, ValueError):  # pragma: no cover - realpath is near-total
        aliases.add(os.path.realpath(value))
    return frozenset(aliases)


def _image_mount_points(image: dict[str, Any]) -> tuple[str, ...]:
    entities = image.get("system-entities")
    if not isinstance(entities, list):
        return ()
    found = [
        entity.get("mount-point")
        for entity in entities
        if isinstance(entity, dict) and isinstance(entity.get("mount-point"), str)
    ]
    return tuple(point for point in found if point)


def _whole_disk_dev_entry(image: dict[str, Any]) -> str | None:
    """The image's whole-disk node: the entity with no mount point, else the first."""
    entities = image.get("system-entities")
    if not isinstance(entities, list):
        return None
    dicts = [entity for entity in entities if isinstance(entity, dict)]
    for entity in dicts:
        dev_entry = entity.get("dev-entry")
        if isinstance(dev_entry, str) and entity.get("mount-point") is None:
            return dev_entry
    for entity in dicts:
        dev_entry = entity.get("dev-entry")
        if isinstance(dev_entry, str):
            return dev_entry
    return None


def attached_image_device(image_path: Path, *, run: SubprocessRunner = DEFAULT_RUNNER) -> AttachedImage | None:
    """Find *image_path* among the currently attached disk images, or ``None``.

    Answers "is the secure volume live *somewhere*?" — the question
    ``os.path.ismount(<configured mount point>)`` cannot answer. An image
    attached by Finder, or by a bare ``hdiutil attach`` with no
    ``-mountpoint``, auto-mounts under ``/Volumes/<volname>``; treating that
    as "locked" because nothing is at the configured path would be exactly the
    false assurance this feature exists to avoid. Raises
    :class:`SecureHomeProbeError` when ``hdiutil`` itself fails — the caller
    must refuse rather than assume "not attached".
    """
    plist = _run_plist_tool(("hdiutil", "info", "-plist"), run=run, timeout=_HDIUTIL_INFO_TIMEOUT)
    images = plist.get("images")
    if not isinstance(images, list):
        return None
    wanted = _path_aliases(str(image_path))
    for image in images:
        if not isinstance(image, dict):
            continue
        candidate = _parse_str(image, "image-path")
        if candidate is None or not (wanted & _path_aliases(candidate)):
            continue
        device_node = _whole_disk_dev_entry(image)
        if device_node is not None:
            return AttachedImage(device_node=device_node, mount_points=_image_mount_points(image))
    return None


def native_volume_state(volume_uuid: str, *, run: SubprocessRunner = DEFAULT_RUNNER) -> tuple[bool | None, str | None]:
    """``(locked, mount_point)`` for a native APFS volume, by UUID.

    ``(None, None)`` when ``diskutil`` exits non-zero — the volume is not
    present on this Mac (an external disk that was unplugged, say), which is
    an answer, not a failure. ``locked`` is ``None`` when the key is absent,
    so callers must fail closed on the distinction rather than read a missing
    key as "unlocked". An invocation failure or unparsable output still raises
    :class:`SecureHomeProbeError`.
    """
    argv = ("diskutil", "info", "-plist", volume_uuid)
    result = _invoke_plist_tool(argv, run=run, timeout=_VOLUME_INFO_TIMEOUT)
    if result.returncode != 0:
        return None, None
    plist = _parse_plist_output(argv, result.stdout or "")
    return _parse_bool(plist, "Locked"), (_parse_str(plist, "MountPoint") or None)


BOOT_VOLUME: Final[str] = "BOOT_VOLUME"
NOT_MOUNTED: Final[str] = "NOT_MOUNTED"
PROBE_FAILED: Final[str] = "PROBE_FAILED"
UUID_MISMATCH: Final[str] = "UUID_MISMATCH"
NOT_APFS: Final[str] = "NOT_APFS"
NOT_ENCRYPTED: Final[str] = "NOT_ENCRYPTED"
OWNERSHIP_DISABLED: Final[str] = "OWNERSHIP_DISABLED"
HOME_MISSING: Final[str] = "HOME_MISSING"
UNSAFE_HOME: Final[str] = "UNSAFE_HOME"


class SecureHomeVerificationError(Exception):
    """One failed step of the :func:`verify_home` chain.

    ``code`` is one of the module-level ``Final[str]`` constants above, so
    callers (the CLI layer) can branch on it without string-matching the
    message.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerifiedHome:
    """The outcome of a successful :func:`verify_home` call."""

    home: Path
    mount_point: Path
    volume_uuid: str
    device_node: str | None


def inspect_mounted_volume(
    mount_point: Path,
    *,
    run: SubprocessRunner = DEFAULT_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
) -> VolumeInfo:
    """Chain steps 1-3: symlink-free path, really mounted, ``diskutil``-probed.

    Shared by :func:`verify_home` and ``adopt`` so both judge a candidate
    mountpoint by exactly the same rules — ``adopt`` must not be able to
    record a volume that ``run`` would then refuse for a step this function
    covers.
    """
    _verify_mount_point_safe(mount_point)
    _verify_mounted(mount_point, ismount)
    return _probe_volume(mount_point, run)


def ensure_volume_acceptable(info: VolumeInfo, mount_point: Path, *, run: SubprocessRunner = DEFAULT_RUNNER) -> None:
    """Chain steps 5-8: APFS, not a boot/system volume, encrypted, ownership honored.

    Shared by :func:`verify_home` and ``adopt`` — the acceptance policy must
    have exactly one definition. Raises :class:`SecureHomeVerificationError`
    on the first failed step, fail closed on every unknown.
    """
    _verify_filesystem(info.filesystem)
    _verify_not_boot_volume(info, mount_point)
    _verify_encryption(info, run=run)
    _verify_ownership(info)


def verify_mounted_identity(
    config: SecureHomeConfig,
    *,
    run: SubprocessRunner = DEFAULT_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
) -> VolumeInfo:
    """Chain steps 1-4 only: symlink-free mountpoint, really mounted, diskutil-probed, UUID matches.

    Deliberately stops short of :func:`ensure_volume_acceptable` and the
    home-dir checks — callers that only need to confirm "is the volume I'm
    about to act on genuinely the one this config describes" (notably an
    ``unmount`` path, which must never detach a foreign volume just because
    something is mounted at the configured path) must not also be refused
    over an acceptance concern like a noowners mount, which has nothing to
    do with volume identity.
    """
    info = inspect_mounted_volume(config.mount_point, run=run, ismount=ismount)
    _verify_uuid(config.volume_uuid, info.volume_uuid)
    return info


def verify_home(
    config: SecureHomeConfig,
    *,
    run: SubprocessRunner = DEFAULT_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
    require_home: bool = True,
) -> VerifiedHome:
    """Fail-closed verification chain: is it safe to run Hermes against this home?

    Each step raises :class:`SecureHomeVerificationError` on the *first*
    failure, in this fixed order — mounted, then genuinely the configured
    volume (UUID), then an acceptable volume (APFS, non-boot, encrypted,
    ownership honored), then (unless ``require_home=False``) a safe existing
    home directory. Later steps assume everything before them held, so the
    order is load-bearing: e.g. we never inspect ``home_path`` on a volume
    we haven't yet confirmed is the right one. The first two steps are
    shared with :func:`verify_mounted_identity` so both judge "is this the
    right volume" by exactly the same rule.
    """
    info = verify_mounted_identity(config, run=run, ismount=ismount)
    ensure_volume_acceptable(info, config.mount_point, run=run)
    if require_home:
        _verify_home_dir(config.mount_point, config.home_path)
    return VerifiedHome(
        home=config.home_path,
        mount_point=config.mount_point,
        volume_uuid=config.volume_uuid,
        device_node=info.device_node,
    )


def _refuse_symlink_component(path: Path) -> None:
    """Raise :data:`UNSAFE_HOME` on the first existing symlinked component of *path*."""
    for component in (*reversed(path.parents), path):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            # ValueError: an embedded NUL byte — refusable input, not a crash.
            raise SecureHomeVerificationError(
                UNSAFE_HOME, f"Could not safely inspect path component: {component}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise SecureHomeVerificationError(UNSAFE_HOME, f"Refusing: {component} is a symlink.")


def _verify_mount_point_safe(mount_point: Path) -> None:
    _refuse_symlink_component(mount_point)


def _verify_mounted(mount_point: Path, ismount: Callable[[str], bool]) -> None:
    if not ismount(str(mount_point)):
        raise SecureHomeVerificationError(
            NOT_MOUNTED,
            "Secure Hermes home is locked. Unlock it to continue. "
            f"Expected the encrypted volume mounted at {mount_point}.",
        )


def _probe_volume(mount_point: Path, run: SubprocessRunner) -> VolumeInfo:
    try:
        return volume_info(mount_point, run=run)
    except SecureHomeProbeError as exc:
        raise SecureHomeVerificationError(PROBE_FAILED, f"Could not verify the mounted volume: {exc}") from exc


def _verify_uuid(expected: str, found: str | None) -> None:
    """Compare as parsed UUIDs — no casefold tricks, no format confusion."""
    mismatch = SecureHomeVerificationError(
        UUID_MISMATCH,
        f"A different volume is mounted at the configured path. Expected volume UUID {expected}, found {found!r}.",
    )
    if found is None:
        raise mismatch
    try:
        expected_uuid = uuid_module.UUID(expected)
        found_uuid = uuid_module.UUID(found)
    except ValueError:
        raise mismatch from None
    if found_uuid != expected_uuid:
        raise mismatch


_ACCEPTED_FILESYSTEMS: Final[frozenset[str]] = frozenset({"apfs", "case-sensitive apfs"})


def _verify_filesystem(filesystem: str | None) -> None:
    if filesystem is None or filesystem.casefold() not in _ACCEPTED_FILESYSTEMS:
        raise SecureHomeVerificationError(
            NOT_APFS, f"Secure Hermes home requires an APFS volume; found {filesystem!r}."
        )


_REFUSED_MOUNT_PREFIX: Final[str] = "/System/Volumes/"


def _is_boot_mount(candidate: str | None) -> bool:
    return candidate is not None and (candidate == "/" or candidate.startswith(_REFUSED_MOUNT_PREFIX))


def _verify_not_boot_volume(info: VolumeInfo, mount_point: Path) -> None:
    """The boot/system volumes are FileVault-protected, auto-unlocked at boot.

    Adopting one would "verify" while providing none of the independent
    second key layer this feature promises — a false-assurance failure worse
    than an honest refusal.
    """
    if _is_boot_mount(info.mount_point) or _is_boot_mount(str(mount_point)):
        raise SecureHomeVerificationError(
            BOOT_VOLUME,
            "The configured path is on the boot/system volume, which is protected only by "
            "FileVault and auto-unlocked at every boot. secure-home requires a separate "
            "encrypted APFS volume.",
        )


def _verify_encryption(info: VolumeInfo, *, run: SubprocessRunner) -> None:
    """Accept a natively encrypted APFS volume or an encrypted backing disk image."""
    if info.encryption_this_volume_proper is True:
        return
    if info.device_node is not None:
        try:
            image_encrypted = _image_backed_encrypted(info.device_node, run=run)
        except SecureHomeProbeError as exc:
            raise SecureHomeVerificationError(
                PROBE_FAILED, f"Could not verify the backing disk image's encryption: {exc}"
            ) from exc
        if image_encrypted is True:
            return
    raise SecureHomeVerificationError(
        NOT_ENCRYPTED,
        "Secure Hermes home requires an encrypted volume, and the mounted volume did not "
        "report as encrypted (neither the APFS volume itself nor a backing encrypted disk image).",
    )


def _verify_ownership(info: VolumeInfo) -> None:
    """Refuse ``noowners`` mounts — there, every user is the owner and 0700 protects nothing."""
    if info.ownership_enabled is not True:
        raise SecureHomeVerificationError(
            OWNERSHIP_DISABLED,
            "The volume ignores file ownership (mounted noowners), so permissions cannot "
            "protect the secure home from other local users. Re-attach it with "
            "'hdiutil attach -owners on ...' or enable ownership with "
            "'sudo diskutil enableOwnership <mountpoint>'.",
        )


def _verify_home_dir(mount_point: Path, home_path: Path) -> None:
    """Final step: the home directory must exist, be safe, be ours, and be on the verified volume.

    Never creates anything.
    """
    _refuse_symlink_component(home_path)

    try:
        metadata = home_path.lstat()
    except FileNotFoundError:
        raise SecureHomeVerificationError(
            HOME_MISSING, f"Secure Hermes home directory does not exist: {home_path}"
        ) from None
    except (OSError, ValueError) as exc:
        raise SecureHomeVerificationError(
            UNSAFE_HOME, f"Could not inspect secure Hermes home: {home_path}: {exc}"
        ) from exc

    if not stat.S_ISDIR(metadata.st_mode):
        raise SecureHomeVerificationError(UNSAFE_HOME, f"Secure Hermes home is not a directory: {home_path}")
    if _geteuid is not None and metadata.st_uid != _geteuid():
        raise SecureHomeVerificationError(
            UNSAFE_HOME, f"Secure Hermes home is not owned by the current user: {home_path}"
        )
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SecureHomeVerificationError(
            UNSAFE_HOME, f"Secure Hermes home must not be group- or other-writable: {home_path}"
        )
    _verify_same_device(mount_point, home_path, metadata)


def _verify_same_device(mount_point: Path, home_path: Path, home_metadata: os.stat_result) -> None:
    """Device continuity: the home must live on the very filesystem we just verified."""
    try:
        mount_dev = os.lstat(mount_point).st_dev
    except (OSError, ValueError) as exc:
        raise SecureHomeVerificationError(
            UNSAFE_HOME, f"Could not inspect the mount point device: {mount_point}: {exc}"
        ) from exc
    if home_metadata.st_dev != mount_dev:
        raise SecureHomeVerificationError(
            UNSAFE_HOME,
            f"Secure Hermes home is not on the verified volume (a nested mount or firmlink redirects {home_path}).",
        )
