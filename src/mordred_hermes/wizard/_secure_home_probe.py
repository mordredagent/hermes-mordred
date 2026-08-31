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
    "FileVaultState",
    "SecureHomeProbeError",
    "SecureHomeVerificationError",
    "SubprocessRunner",
    "VerifiedHome",
    "VolumeInfo",
    "ensure_volume_acceptable",
    "filevault_status",
    "inspect_mounted_volume",
    "verify_home",
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


def _run_plist_tool(argv: tuple[str, ...], *, run: SubprocessRunner, timeout: float) -> dict[str, Any]:
    """Invoke a plist-emitting system tool, failing closed into :class:`SecureHomeProbeError`."""
    try:
        result = run(argv, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecureHomeProbeError(f"{' '.join(argv)!r} failed or timed out: {exc}") from exc
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        raise SecureHomeProbeError(f"{' '.join(argv)!r} failed (rc={result.returncode}): {detail!r}")

    try:
        parsed = plistlib.loads((result.stdout or "").encode())
    except _PLIST_PARSE_ERRORS as exc:
        raise SecureHomeProbeError(f"{' '.join(argv)!r} produced unparsable plist output: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SecureHomeProbeError(f"{' '.join(argv)!r} plist output is not a dictionary")
    return parsed


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


def _image_backed_encrypted(device_node: str, *, run: SubprocessRunner) -> bool | None:
    """Whether the attached disk image backing *device_node* is encrypted.

    Returns ``None`` when no attached image owns the device (the volume is
    not image-backed at all); ``False`` when an image owns it but does not
    report ``image-encrypted`` true — an image found without the flag is
    treated as unencrypted, never as unknown. Raises
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
            return _parse_bool(image, "image-encrypted") is True
    return None


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
    we haven't yet confirmed is the right one.
    """
    info = inspect_mounted_volume(config.mount_point, run=run, ismount=ismount)
    _verify_uuid(config.volume_uuid, info.volume_uuid)
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
