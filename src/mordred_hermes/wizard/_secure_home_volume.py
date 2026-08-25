"""Thin, injectable wrappers over ``hdiutil``/``diskutil`` volume mutation.

Every other secure-home module is either read-only (``_secure_home_probe``)
or policy/config-only (``_secure_home_paths``, ``secure_home_cli``). This
module is the *only* one that mutates a volume — create a fresh encrypted
disk image, attach/detach it, or unlock/lock a natively encrypted APFS
volume. It carries zero policy of its own: no verification (that's
``_secure_home_probe.verify_home``), no config I/O, no prompting. Callers
decide *whether* and *when* to call these; this module only decides *how* to
call the underlying tool safely.

The central security property is that a volume passphrase must reach
``hdiutil``/``diskutil`` ONLY via the process's stdin. It must never appear
in ``argv`` (visible to every other local process via ``ps``), and it must
never be embedded in a raised exception or log message — an operator's
passphrase leaking into an error report handed to support, a CI log, or a
crash reporter would defeat the whole point of secure-home. Every function
here validates its non-secret inputs (paths, sizes, names, UUIDs) before
ever invoking a subprocess, so a malformed argument fails as a plain
``ValueError`` instead of reaching a shell-adjacent tool at all.

``hdiutil -stdinpass`` and ``diskutil ... -stdinpassphrase`` frame the
passphrase differently: ``man hdiutil`` documents ``-stdinpass`` as reading a
*null-terminated* passphrase from standard input, while ``diskutil`` reads a
single ``\\n``-terminated line (confirmed against a real device).
``create_encrypted_image`` and ``attach_image`` therefore pass the passphrase
exactly as given; ``unlock_native_volume`` appends
:data:`DISKUTIL_STDIN_TERMINATOR` — kept as a single named constant precisely
so this detail is easy to revisit if a future macOS release changes it.
Because both framings are terminator-based, a passphrase containing ``"\\n"``
or ``"\\x00"`` cannot round-trip (the tool would silently accept a truncated
prefix and create a volume nobody can reopen), so
:func:`_validate_passphrase` refuses both before any tool runs.

The stdin encoding is pinned to UTF-8 rather than inherited from the process
locale. Without the pin, ``subprocess``'s ``text=True`` encodes ``input=``
with the parent's preferred encoding, so a non-ASCII passphrase chosen from a
UTF-8 terminal would be sent as different bytes from a ``cron``/``ssh``/
``launchd`` context (``'päss'`` → ``70 c3 a4 73 73`` vs. ``70 e4 73 73``) and
the volume would be unopenable there. ``errors="strict"`` makes an
unencodable passphrase a clean refusal instead of a ``UnicodeEncodeError``
whose text quotes the offending character and its offset.

Every subprocess call goes through an injectable :class:`VolumeRunner` —
mirroring ``_secure_home_probe.SubprocessRunner`` — so unit tests never
invoke a real ``hdiutil``/``diskutil`` and never touch a real volume. The
default runner pins the same minimal ``PATH``/``LC_ALL`` environment as the
probe module (imported, not duplicated, so the two can never drift), and
uses ``stdin=subprocess.DEVNULL`` whenever no ``input`` is supplied — a
mutating tool must never be able to fall back to prompting on an inherited
TTY and hang the caller.
"""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
import uuid as uuid_module
import xml.parsers.expat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from ._secure_home_probe import _PINNED_ENV

__all__ = [
    "ATTACH_FAILED",
    "CREATE_FAILED",
    "DEFAULT_VOLUME_RUNNER",
    "DETACH_FAILED",
    "DISKUTIL_STDIN_TERMINATOR",
    "LOCK_FAILED",
    "TOOL_FAILED",
    "UNLOCK_FAILED",
    "VOLUME_BUSY",
    "AttachResult",
    "SecureHomeVolumeError",
    "VolumeRunner",
    "attach_image",
    "create_encrypted_image",
    "detach",
    "force_unmount_native",
    "lock_native_volume",
    "unlock_native_volume",
]

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
_CREATE_TIMEOUT: Final[float] = 300.0
_ATTACH_TIMEOUT: Final[float] = 120.0
_UNLOCK_TIMEOUT: Final[float] = 120.0
_DETACH_TIMEOUT: Final[float] = 60.0
_LOCK_TIMEOUT: Final[float] = 60.0

CREATE_FAILED: Final[str] = "CREATE_FAILED"
ATTACH_FAILED: Final[str] = "ATTACH_FAILED"
UNLOCK_FAILED: Final[str] = "UNLOCK_FAILED"
DETACH_FAILED: Final[str] = "DETACH_FAILED"
LOCK_FAILED: Final[str] = "LOCK_FAILED"
VOLUME_BUSY: Final[str] = "VOLUME_BUSY"
TOOL_FAILED: Final[str] = "TOOL_FAILED"

#: ``diskutil apfs unlockVolume -stdinpassphrase`` reads a single terminated
#: line, unlike ``hdiutil -stdinpass`` (raw bytes to EOF) — see module
#: docstring. Named so the one place this assumption lives is unmistakable.
DISKUTIL_STDIN_TERMINATOR: Final[str] = "\n"

_STDERR_TRIM_LIMIT: Final[int] = 200

# Mirrors _secure_home_probe._PLIST_PARSE_ERRORS: a truncated-but-well-headed
# plist body raises ExpatError, which is NOT a ValueError — lenient parsing
# here must not let a flaky `hdiutil attach` escape as a raw traceback.
_PLIST_PARSE_ERRORS: Final = (plistlib.InvalidFileException, ValueError, xml.parsers.expat.ExpatError)

# `\Z`, not `$`: `$` also matches just before a trailing newline, so "4g\n"
# would pass and then reach hdiutil as a two-line argument.
_SIZE_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]+[bkmgt]?\Z")
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")
_MAX_VOLUME_NAME_LEN: Final[int] = 64
#: A freshly created image inherits the umask (0644 by default), leaving a
#: world-readable, freely copyable ciphertext blob whose only remaining
#: control is the passphrase. 0600 does not stop root or a backup agent,
#: but it does stop every other local account from taking a copy home.
_IMAGE_MODE: Final[int] = 0o600


# -----------------------------------------------------------------------------
# Runner
# -----------------------------------------------------------------------------
class VolumeRunner(Protocol):
    """The injectable command runner contract for volume mutation calls.

    Unlike ``_secure_home_probe.SubprocessRunner`` (read-only, never takes
    stdin input), every call site here may need to feed a passphrase to the
    tool — hence the ``input`` keyword, which is the *only* channel a
    passphrase is ever allowed to travel through.
    """

    def __call__(
        self, argv: Sequence[str], *, timeout: float, input: str | None = None
    ) -> subprocess.CompletedProcess[str]: ...


def _default_volume_runner(
    argv: Sequence[str], *, timeout: float, input: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Production default: a real ``subprocess.run`` with a pinned minimal env.

    ``stdin=subprocess.DEVNULL`` when no ``input`` is given: a mutating tool
    invoked with no passphrase to feed it must never be able to fall back to
    prompting on an inherited TTY and hang the caller. ``encoding``/``errors``
    are pinned rather than inherited from the locale — see the module
    docstring for why a locale-dependent passphrase encoding is a data-loss
    bug.
    """
    if input is not None:
        return subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
            timeout=timeout,
            env=_PINNED_ENV,
            input=input,
        )
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        timeout=timeout,
        env=_PINNED_ENV,
        stdin=subprocess.DEVNULL,
    )


DEFAULT_VOLUME_RUNNER: Final[VolumeRunner] = _default_volume_runner


class SecureHomeVolumeError(Exception):
    """Raised when a volume-mutating ``hdiutil``/``diskutil`` call fails.

    ``code`` is one of the module-level ``Final[str]`` constants above, so
    callers can branch on it without string-matching the message. The
    message always includes the tool name and a trimmed excerpt of its
    stderr/stdout — never the passphrase, which never reaches ``argv`` or
    any exception this module raises.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _trim(text: str, limit: int = _STDERR_TRIM_LIMIT) -> str:
    stripped = text.strip()
    return stripped if len(stripped) <= limit else stripped[:limit]


def _is_busy(text: str) -> bool:
    """``"Resource busy"`` or bare ``"busy"``, case-insensitive — the latter subsumes the former."""
    return "busy" in text.casefold()


def _wrong_passphrase_hint(text: str) -> str:
    lowered = text.casefold()
    if "authentication" in lowered or "passphrase" in lowered:
        return " — wrong passphrase?"
    return ""


def _invoke(
    argv: Sequence[str],
    *,
    timeout: float,
    input: str | None,
    run: VolumeRunner,
    tool_label: str,
) -> subprocess.CompletedProcess[str]:
    """Run *argv* through the injected runner, failing closed into :class:`SecureHomeVolumeError`.

    Only ``argv`` and ``timeout`` (never the passphrase) can appear in the
    raised message: the caught exception text originates from the
    runner/OS describing the failed invocation, not from us echoing *input*.

    The two ``UnicodeError`` branches are deliberately text-free.
    ``UnicodeEncodeError`` is raised while encoding *the passphrase* and its
    ``str()`` quotes the offending character and its offset — a partial
    passphrase disclosure into whatever log or bug report the message reaches.
    ``UnicodeDecodeError`` (undecodable tool output) is quoted-bytes noise
    with nothing actionable in it. Both are ``ValueError`` subclasses, so
    neither is covered by the ``OSError``/``SubprocessError`` branch below.
    """
    try:
        return run(argv, timeout=timeout, input=input)
    except UnicodeEncodeError as exc:
        raise SecureHomeVolumeError(
            TOOL_FAILED, f"{tool_label}: the passphrase contains a character that cannot be encoded as UTF-8"
        ) from exc
    except UnicodeDecodeError as exc:
        raise SecureHomeVolumeError(TOOL_FAILED, f"{tool_label} produced output that is not valid UTF-8") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecureHomeVolumeError(TOOL_FAILED, f"{tool_label} failed or timed out: {exc}") from exc


# -----------------------------------------------------------------------------
# Input validation — all raised BEFORE any subprocess call
# -----------------------------------------------------------------------------
def _validate_image_path(image_path: Path) -> None:
    if not image_path.is_absolute():
        raise ValueError(f"secure-home image_path must be an absolute path: {image_path}")


def _validate_size(size: str) -> None:
    if _SIZE_RE.match(size.casefold()) is None:
        raise ValueError(f"secure-home image size is invalid: {size!r}")


def _validate_volume_name(volume_name: str) -> None:
    if not volume_name:
        raise ValueError("secure-home volume_name must not be empty")
    if len(volume_name) > _MAX_VOLUME_NAME_LEN:
        raise ValueError(f"secure-home volume_name must be at most {_MAX_VOLUME_NAME_LEN} characters: {volume_name!r}")
    if _CONTROL_CHAR_RE.search(volume_name):
        raise ValueError(f"secure-home volume_name must not contain control characters: {volume_name!r}")
    if "/" in volume_name:
        raise ValueError(f"secure-home volume_name must not contain '/': {volume_name!r}")
    if volume_name.startswith("-"):
        raise ValueError(f"secure-home volume_name must not start with '-': {volume_name!r}")


def _validate_passphrase(passphrase: str) -> None:
    """Refuse a passphrase the tools' stdin framing cannot carry intact.

    Never echoes the value — only the fact and the offending class of
    character, so the message is safe to print, log, or paste into a report.
    """
    if not passphrase:
        raise ValueError("secure-home passphrase must not be empty")
    if "\n" in passphrase:
        raise ValueError("secure-home passphrase must not contain a newline (the tools read a terminated line)")
    if "\x00" in passphrase:
        raise ValueError("secure-home passphrase must not contain a NUL character (hdiutil reads to the first NUL)")


def _validate_mount_point(mount_point: Path) -> None:
    """Every path handed to a mutating tool must be absolute.

    ``hdiutil``/``diskutil`` resolve a relative path against *their* working
    directory, which is ours only by accident; and a bare word could be read
    as a flag. Also accepts a ``/dev/...`` node, which is absolute by
    construction (``detach`` may be given one instead of a mount point).
    """
    if not mount_point.is_absolute():
        raise ValueError(f"secure-home mount point must be an absolute path: {mount_point}")


def _validate_uuid(volume_uuid: str) -> None:
    try:
        uuid_module.UUID(volume_uuid)
    except ValueError as exc:
        raise ValueError(f"secure-home volume_uuid is not a valid UUID: {volume_uuid!r}") from exc


# -----------------------------------------------------------------------------
# create
# -----------------------------------------------------------------------------
def create_encrypted_image(
    image_path: Path,
    *,
    size: str,
    volume_name: str,
    passphrase: str,
    run: VolumeRunner = DEFAULT_VOLUME_RUNNER,
) -> None:
    """Create a new sparse, natively-encrypted-APFS disk image at *image_path*.

    The passphrase reaches ``hdiutil`` ONLY via stdin (``-stdinpass``),
    exactly as given — no trailing newline, because ``-stdinpass`` reads a
    null-terminated passphrase and an appended ``"\\n"`` would become part of
    the passphrase itself. On success the image is chmod-ed to
    :data:`_IMAGE_MODE`.
    """
    _validate_image_path(image_path)
    _validate_size(size)
    _validate_volume_name(volume_name)
    _validate_passphrase(passphrase)
    argv = (
        "hdiutil",
        "create",
        "-size",
        size,
        "-type",
        "SPARSE",
        "-fs",
        "APFS",
        "-encryption",
        "AES-256",
        "-stdinpass",
        "-volname",
        volume_name,
        str(image_path),
    )
    result = _invoke(argv, timeout=_CREATE_TIMEOUT, input=passphrase, run=run, tool_label="hdiutil create")
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        raise SecureHomeVolumeError(CREATE_FAILED, f"hdiutil create failed (rc={result.returncode}): {detail}")
    try:
        os.chmod(image_path, _IMAGE_MODE)
    except OSError as exc:
        # Reported as CREATE_FAILED on purpose: the caller's rollback then
        # removes the image, rather than leaving a usable but world-readable
        # one behind on the strength of "well, create did succeed".
        raise SecureHomeVolumeError(
            CREATE_FAILED, f"hdiutil create succeeded but the image could not be restricted to 0600: {exc}"
        ) from exc


# -----------------------------------------------------------------------------
# attach / detach
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class AttachResult:
    """The outcome of a successful :func:`attach_image` call."""

    device_node: str | None
    mount_point: Path


def attach_image(
    image_path: Path,
    mount_point: Path,
    *,
    passphrase: str,
    run: VolumeRunner = DEFAULT_VOLUME_RUNNER,
) -> AttachResult:
    """Attach the encrypted disk image at *image_path*, mounting it at *mount_point*.

    The passphrase reaches ``hdiutil`` ONLY via stdin (``-stdinpass``),
    exactly as given (see :func:`create_encrypted_image`). On success, the
    device node is parsed leniently from ``hdiutil``'s plist output: an
    unparsable or unexpected shape returns ``AttachResult(None, mount_point)``
    rather than raising, because the caller re-verifies the mount
    independently (``_secure_home_probe.verify_mounted_identity``) and a
    missing device node there is harmless.
    """
    _validate_image_path(image_path)
    _validate_mount_point(mount_point)
    _validate_passphrase(passphrase)
    argv = (
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
    result = _invoke(argv, timeout=_ATTACH_TIMEOUT, input=passphrase, run=run, tool_label="hdiutil attach")
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        hint = _wrong_passphrase_hint(detail)
        raise SecureHomeVolumeError(ATTACH_FAILED, f"hdiutil attach failed (rc={result.returncode}): {detail}{hint}")
    return _parse_attach_plist(result.stdout or "", mount_point)


def _parse_attach_plist(stdout: str, mount_point: Path) -> AttachResult:
    try:
        parsed = plistlib.loads(stdout.encode())
    except _PLIST_PARSE_ERRORS:
        return AttachResult(None, mount_point)
    if not isinstance(parsed, dict):
        return AttachResult(None, mount_point)
    entities = parsed.get("system-entities")
    if not isinstance(entities, list):
        return AttachResult(None, mount_point)

    dict_entities = [entity for entity in entities if isinstance(entity, dict)]
    target = str(mount_point)

    for entity in dict_entities:
        dev_entry = entity.get("dev-entry")
        if isinstance(dev_entry, str) and entity.get("mount-point") == target:
            return AttachResult(dev_entry, mount_point)
    for entity in dict_entities:
        dev_entry = entity.get("dev-entry")
        if isinstance(dev_entry, str) and isinstance(entity.get("mount-point"), str):
            return AttachResult(dev_entry, mount_point)
    return AttachResult(None, mount_point)


def detach(mount_point: Path, *, force: bool = False, run: VolumeRunner = DEFAULT_VOLUME_RUNNER) -> None:
    """Detach (unmount + eject) the disk image mounted at *mount_point*.

    Also accepts a ``/dev/diskN`` node, which is what ``hdiutil`` reports for
    an image attached somewhere other than the path we expected.
    """
    _validate_mount_point(mount_point)
    argv: tuple[str, ...] = ("hdiutil", "detach", str(mount_point), *(("-force",) if force else ()))
    result = _invoke(argv, timeout=_DETACH_TIMEOUT, input=None, run=run, tool_label="hdiutil detach")
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        code = VOLUME_BUSY if _is_busy(detail) else DETACH_FAILED
        raise SecureHomeVolumeError(code, f"hdiutil detach failed (rc={result.returncode}): {detail}")


# -----------------------------------------------------------------------------
# native APFS volume unlock / lock
# -----------------------------------------------------------------------------
def unlock_native_volume(
    volume_uuid: str,
    mount_point: Path,
    *,
    passphrase: str,
    run: VolumeRunner = DEFAULT_VOLUME_RUNNER,
) -> None:
    """Unlock and mount a natively-encrypted APFS volume identified by *volume_uuid*.

    Unlike ``hdiutil -stdinpass``, ``diskutil ... -stdinpassphrase`` reads a
    single terminated line, so the passphrase is sent with exactly one
    trailing :data:`DISKUTIL_STDIN_TERMINATOR` appended — never zero, never
    more than one.
    """
    _validate_uuid(volume_uuid)
    _validate_mount_point(mount_point)
    _validate_passphrase(passphrase)
    argv = (
        "diskutil",
        "apfs",
        "unlockVolume",
        volume_uuid,
        "-stdinpassphrase",
        "-mountpoint",
        str(mount_point),
    )
    stdin_input = passphrase + DISKUTIL_STDIN_TERMINATOR
    result = _invoke(argv, timeout=_UNLOCK_TIMEOUT, input=stdin_input, run=run, tool_label="diskutil apfs unlockVolume")
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        hint = _wrong_passphrase_hint(detail)
        raise SecureHomeVolumeError(
            UNLOCK_FAILED, f"diskutil apfs unlockVolume failed (rc={result.returncode}): {detail}{hint}"
        )


def lock_native_volume(volume_uuid: str, *, run: VolumeRunner = DEFAULT_VOLUME_RUNNER) -> None:
    """Lock (unmount + re-encrypt) a natively-encrypted APFS volume identified by *volume_uuid*."""
    _validate_uuid(volume_uuid)
    argv = ("diskutil", "apfs", "lockVolume", volume_uuid)
    result = _invoke(argv, timeout=_LOCK_TIMEOUT, input=None, run=run, tool_label="diskutil apfs lockVolume")
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        code = VOLUME_BUSY if _is_busy(detail) else LOCK_FAILED
        raise SecureHomeVolumeError(code, f"diskutil apfs lockVolume failed (rc={result.returncode}): {detail}")


def force_unmount_native(mount_point: Path, *, run: VolumeRunner = DEFAULT_VOLUME_RUNNER) -> None:
    """Force-unmount whatever is mounted at *mount_point* via ``diskutil unmount force``.

    A last-resort escape hatch (e.g. a stuck native volume that ``lock``
    alone cannot clear) — deliberately narrower than :func:`detach`'s busy
    handling, since a caller reaching for *force* has already chosen to
    override a busy volume rather than be told about one.
    """
    _validate_mount_point(mount_point)
    argv = ("diskutil", "unmount", "force", str(mount_point))
    result = _invoke(argv, timeout=_DETACH_TIMEOUT, input=None, run=run, tool_label="diskutil unmount force")
    if result.returncode != 0:
        detail = _trim(result.stderr or result.stdout or "")
        raise SecureHomeVolumeError(DETACH_FAILED, f"diskutil unmount force failed (rc={result.returncode}): {detail}")
