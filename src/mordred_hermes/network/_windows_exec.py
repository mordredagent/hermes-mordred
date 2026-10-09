"""Checked native Windows executable discovery for Mordred-launched route commands.

Every executable the network component starts on Windows (``tor_binary`` and
each ``custom_*_cmd`` image) is resolved here to one absolute ``.exe`` path
before any process is created; the resolved path is then passed as both the
explicit image and ``argv[0]`` of an argument list, never through a shell.

Discovery differs deliberately from ``CreateProcess`` / ``shutil.which``:

- Only ``.exe`` images are accepted. ``.cmd``/``.bat`` would run through
  ``cmd.exe`` with its own quoting rules; ``.com``, scripts and extensionless
  absolute paths are refused too. A bare name without an extension gains
  ``.exe``.
- A path with a directory component must be absolute with a drive. Relative,
  drive-relative, UNC and device-namespace paths are refused.
- A bare name is looked up only in absolute, non-UNC ``PATH`` entries. The
  current directory, relative ``PATH`` entries and the App Paths registry are
  never consulted.

The resolved image is then classified with existing private-filesystem
capabilities; nothing here repairs an ACL or writes anything:

- ``managed``: admitted by ``inspect_managed_installation_image`` (an
  administrator/OS-managed installation such as ``C:\\Program Files``).
- ``user-private``: owned by the current user inside a checked
  confidential (or private) directory. Default per-user ACL directories
  such as ``%TEMP%`` or ``Downloads`` are user-private and admitted, because
  the threat model is other principals (controller ruling R-C9-2).
- ``untrusted``: anything else, i.e. an image in a directory other principals
  can change, e.g. ``C:\\tools`` created under ``C:\\`` (inheriting the
  Authenticated Users modify grant), ``C:\\Users\\Public`` or a directory with
  an Everyone grant.

Strict policy refuses an untrusted image; lenient/off log a warning and
continue. Refusal messages name only a sanitized basename, never the
directory or any argument.
"""

from __future__ import annotations

import logging
import ntpath
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

from .._policy_types import PolicyMode
from .._private_fs import PrivateFSError, inspect_managed_installation_image, open_optional_confidential_directory
from ._exceptions import BringupFailed

__all__ = [
    "ExecutableRefused",
    "ExecutableTrust",
    "ResolvedExecutable",
    "admit_current_user_image",
    "describe_executable",
    "enforce_executable_trust",
    "resolve_windows_executable",
]

_LOG = logging.getLogger("mordred.network.windows_exec")

ExecutableTrust = Literal["managed", "user-private", "untrusted"]

MAX_COMMAND_CHARS: Final[int] = 32767
MAX_PATH_ENTRIES: Final[int] = 512
_FORBIDDEN_NAME_CHARS: Final[frozenset[str]] = frozenset('"<>|?*')
_ADMISSION_REFUSALS: Final[tuple[type[BaseException], ...]] = (OSError, ValueError)

# Module-level seam so host tests can substitute a Windows filesystem view.
_is_file: Callable[[str], bool] = os.path.isfile


class ExecutableRefused(BringupFailed):
    """A classified executable refusal; ``reason`` is a stable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(f"{message} ({reason})")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ResolvedExecutable:
    """One absolute ``.exe`` image and how it was admitted."""

    path: str
    trust: ExecutableTrust


def describe_executable(command: object) -> str:
    """A bounded, printable basename: refusals never echo directories."""
    text = command if isinstance(command, str) else ""
    basename = ntpath.basename(text.replace("/", "\\")) or "<executable>"
    printable = "".join(char if char.isprintable() else "?" for char in basename)
    return repr(printable[:64])


def resolve_windows_executable(
    command: str,
    *,
    purpose: str,
    environ: Mapping[str, str] | None = None,
    is_file: Callable[[str], bool] | None = None,
    admit_managed: Callable[[str], object] | None = None,
    admit_user_private: Callable[[str], object] | None = None,
) -> ResolvedExecutable:
    """Locate ``command`` as one absolute ``.exe`` and classify its image.

    Raises :class:`ExecutableRefused` when no acceptable image exists. An
    untrusted image is returned, not refused: the caller applies the policy
    through :func:`enforce_executable_trust`. Admission errors other than the
    classified filesystem refusals (``OSError``/``ValueError``) propagate.
    """
    checker = is_file if is_file is not None else _is_file
    path = _locate(command, purpose=purpose, environ=os.environ if environ is None else environ, is_file=checker)
    managed = admit_managed if admit_managed is not None else _admit_managed
    private = admit_user_private if admit_user_private is not None else admit_current_user_image
    return ResolvedExecutable(path, _classify(path, managed, private))


def enforce_executable_trust(resolved: ResolvedExecutable, *, policy_mode: PolicyMode, purpose: str) -> None:
    """Strict refuses an untrusted image; lenient/off warn and continue."""
    if resolved.trust != "untrusted":
        return
    message = (
        f"{purpose} executable {describe_executable(resolved.path)} is neither an administrator-managed "
        "installation image nor a current-user file in a checked private directory"
    )
    if policy_mode == "strict":
        raise ExecutableRefused(
            "executable-untrusted-location",
            f"{message}; strict mode refuses it. Install it under an administrator-managed directory "
            "(for example Program Files) or a private per-user directory, then retry",
        )
    _LOG.warning("%s; %s policy continues with this untrusted image", message, policy_mode)


def admit_current_user_image(path: str) -> None:
    """Admit a current-user-owned image inside a checked directory.

    Reuses the confidential-directory capability (private directories pass it
    too): every ancestor is pinned and checked, the parent refuses untrusted
    add-file/delete-child/ACL/ownership rights, and the image must be a
    regular, non-reparse, single-linked file owned by the current token user
    whose effective allows name only that user, SYSTEM or Administrators. No
    ACL is repaired. Raises ``OSError`` (``PrivateFSError``) on refusal.
    """
    parent, name = ntpath.split(path)
    if not parent or not name:
        raise PrivateFSError("unsafe", "executable_path")
    with open_optional_confidential_directory(parent) as directory:
        if directory is None:
            raise PrivateFSError("missing", "executable_parent")
        directory.stat(name)


def _admit_managed(path: str) -> object:
    return inspect_managed_installation_image(path)


def _classify(
    path: str, admit_managed: Callable[[str], object], admit_user_private: Callable[[str], object]
) -> ExecutableTrust:
    try:
        admit_managed(path)
    except _ADMISSION_REFUSALS:
        pass
    else:
        return "managed"
    try:
        admit_user_private(path)
    except _ADMISSION_REFUSALS:
        return "untrusted"
    return "user-private"


def _refuse(reason: str, purpose: str, command: object, detail: str) -> ExecutableRefused:
    return ExecutableRefused(reason, f"{purpose} executable {describe_executable(command)} {detail}")


def _locate(command: str, *, purpose: str, environ: Mapping[str, str], is_file: Callable[[str], bool]) -> str:
    if not isinstance(command, str) or not command or len(command) > MAX_COMMAND_CHARS:
        raise _refuse("executable-name-invalid", purpose, command, "is not a valid Windows executable name")
    # UNC shares and \\?\ / \\.\ device namespaces bypass the checked drive walk.
    if command.startswith(("\\\\", "//")):
        raise _refuse(
            "executable-path-unsupported", purpose, command, "is on a network or device namespace path; refused"
        )
    if any(ord(char) < 0x20 or ord(char) == 0x7F or char in _FORBIDDEN_NAME_CHARS for char in command):
        raise _refuse("executable-name-invalid", purpose, command, "is not a valid Windows executable name")
    drive, _rest = ntpath.splitdrive(command)
    if drive or "\\" in command or "/" in command:
        if not drive or not ntpath.isabs(command):
            raise _refuse("executable-path-relative", purpose, command, "must be an absolute path with a drive letter")
        candidate = ntpath.normpath(command)
        _require_exe(candidate, purpose=purpose, allow_bare=False)
        if not is_file(candidate):
            raise _refuse("executable-not-found", purpose, command, "was not found")
        return candidate
    name = _require_exe(command, purpose=purpose, allow_bare=True)
    for entry in _path_entries(environ):
        candidate = ntpath.join(entry, name)
        if is_file(candidate):
            return ntpath.normpath(candidate)
    raise _refuse(
        "executable-not-found",
        purpose,
        name,
        "was not found in an absolute PATH directory (the current directory is never searched)",
    )


def _require_exe(name: str, *, purpose: str, allow_bare: bool) -> str:
    extension = ntpath.splitext(name)[1]
    if not extension and allow_bare:
        return name + ".exe"
    if extension.casefold() != ".exe":
        raise _refuse("executable-not-exe", purpose, name, "is not an .exe image; only .exe images are accepted")
    return name


def _path_entries(environ: Mapping[str, str]) -> list[str]:
    value = next((item for key, item in environ.items() if key.upper() == "PATH"), "")
    entries: list[str] = []
    for raw in value.split(";")[:MAX_PATH_ENTRIES]:
        entry = raw.strip()
        if len(entry) >= 2 and entry[0] == entry[-1] == '"':
            entry = entry[1:-1].strip()
        if not entry or '"' in entry or any(ord(char) < 0x20 for char in entry):
            continue
        if entry.startswith(("\\\\", "//")):
            continue  # network shares and device namespaces are not trusted search roots
        drive, _rest = ntpath.splitdrive(entry)
        if drive and ntpath.isabs(entry):
            entries.append(entry)
    return entries
