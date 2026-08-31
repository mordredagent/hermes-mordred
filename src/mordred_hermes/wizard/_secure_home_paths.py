"""On-disk config model + persistence for ``hermes-mordred secure-home``.

The secure-home config records *where the encrypted volume lives* — not
secrets. It deliberately lives OUTSIDE the encrypted volume it describes and
OUTSIDE ``HERMES_HOME``: the CLI must be able to read it before the volume is
mounted (bootstrap: "is secure-home configured at all, and if so, what should
I check for?") and before ``HERMES_HOME`` itself can be resolved, since the
whole point of this feature is to point ``HERMES_HOME`` at that volume. The
default location is ``~/.config/hermes-mordred/secure-home.json``, a
plain-permissions per-user config directory that predates any of this.

Because the file is read pre-mount and pre-verification, it is treated as
adversarial input by everything downstream (``_secure_home_probe.verify_home``
trusts nothing it says without independently confirming the mounted volume's
identity). This module's own job is narrower: refuse to load or save through
a symlink, refuse loose permissions or foreign ownership, and refuse a config
that doesn't parse into a well-formed :class:`SecureHomeConfig` — so a
corrupted or tampered file fails closed here rather than producing a
plausible-looking config that ``verify_home`` is trusted to catch later.
Reads go through an ``O_NOFOLLOW`` file descriptor and every check runs on
that descriptor's ``fstat``, so the file that was checked is the file that is
read.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
import uuid as uuid_module
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

__all__ = [
    "CONFIG_VERSION",
    "SecureHomeConfig",
    "SecureHomeConfigError",
    "load_config",
    "resolve_config_path",
    "save_config",
]

CONFIG_VERSION: Final = 1

_ENV_VAR: Final[str] = "MORDRED_SECURE_HOME_CONFIG"
_FILE_MODE: Final[int] = 0o600
_DIR_MODE: Final[int] = 0o700
_O_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
# A well-formed v1 config is well under 1 KiB; anything huge is not ours.
_MAX_CONFIG_BYTES: Final[int] = 64 * 1024

_geteuid = getattr(os, "geteuid", None)

# macOS mounts several top-level directories as symlinks into /private; a
# refusal there is almost always an unresolved override path, not an attack.
_MACOS_SYMLINK_ROOTS: Final[frozenset[str]] = frozenset({"/tmp", "/var", "/etc"})


class SecureHomeConfigError(Exception):
    """Raised for any secure-home config load/save refusal."""


@dataclass(frozen=True)
class SecureHomeConfig:
    """The full identity of a configured secure Hermes home.

    Validated at construction time (``__post_init__``) so a bad value can
    never reach a caller through any path — not just :func:`load_config`,
    but also a value built directly by the CLI layer.
    """

    version: int
    mount_point: Path
    volume_uuid: str
    home_subdir: str = "hermes-home"

    def __post_init__(self) -> None:
        _validate_clean_text(str(self.mount_point), "mount_point")
        if not self.mount_point.is_absolute():
            raise SecureHomeConfigError(f"secure-home mount_point must be an absolute path: {self.mount_point}")
        _validate_volume_uuid(self.volume_uuid)
        _validate_clean_text(self.home_subdir, "home_subdir")
        _validate_home_subdir(self.home_subdir)

    @property
    def home_path(self) -> Path:
        """The Hermes home directory inside the mounted volume."""
        return self.mount_point / self.home_subdir


def _validate_clean_text(value: str, field: str) -> None:
    """Reject NUL/control characters and edge whitespace in path-bearing fields.

    A NUL byte turns later ``lstat`` calls into ``ValueError`` crashes instead
    of refusals, and upstream strips ``HERMES_HOME`` before use — so edge
    whitespace would make the *verified* path differ from the *effective*
    path. Neither may ever survive construction.
    """
    if value != value.strip():
        raise SecureHomeConfigError(f"secure-home {field} must not have leading or trailing whitespace: {value!r}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise SecureHomeConfigError(f"secure-home {field} must not contain control characters: {value!r}")


def _validate_volume_uuid(volume_uuid: str) -> None:
    if not volume_uuid:
        raise SecureHomeConfigError("secure-home volume_uuid must not be empty")
    try:
        uuid_module.UUID(volume_uuid)
    except ValueError as exc:
        raise SecureHomeConfigError(f"secure-home volume_uuid is not a valid UUID: {volume_uuid!r}") from exc


def _validate_home_subdir(home_subdir: str) -> None:
    """``home_subdir`` must be a single plain path component.

    Rejecting ``/`` and NUL blocks it from smuggling in extra path segments
    (or escaping the mount point entirely via an absolute-looking value);
    rejecting ``.``/``..`` blocks the two components that resolve to "the
    mount point itself" or "outside it" without needing a ``/`` at all.
    """
    if not home_subdir or home_subdir in {".", ".."} or "/" in home_subdir or "\0" in home_subdir:
        raise SecureHomeConfigError(f"secure-home home_subdir must be a single plain path component: {home_subdir!r}")


def resolve_config_path(env: Mapping[str, str] | None = None) -> Path:
    """Resolve the secure-home config file path.

    ``MORDRED_SECURE_HOME_CONFIG`` (stripped) wins when set to a non-empty
    value; an unset, empty, or whitespace-only override falls through to the
    default ``~/.config/hermes-mordred/secure-home.json``. ``env=None`` reads
    the real process environment; tests pass an explicit mapping instead.
    """
    active_env: Mapping[str, str] = os.environ if env is None else env
    override = active_env.get(_ENV_VAR)
    if override is not None:
        stripped = override.strip()
        if stripped:
            return Path(stripped)
    return Path.home() / ".config" / "hermes-mordred" / "secure-home.json"


def _resolve_absolute(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def _symlink_hint(component: Path) -> str:
    if str(component) in _MACOS_SYMLINK_ROOTS:
        return f" (macOS note: {component} is an OS symlink into /private — use the resolved /private{component} path)"
    return ""


def _first_symlink_component(path: Path) -> Path | None:
    """Return the first existing symlinked component of *path* (root..leaf), else ``None``.

    A missing component is skipped, not flagged — a not-yet-created config
    directory must not be refused just because it doesn't exist yet, and
    :func:`save_config` relies on that to create it fresh.
    """
    for component in (*reversed(path.parents), path):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            # ValueError: an embedded NUL byte — refusable input, not a crash.
            raise SecureHomeConfigError(
                f"could not inspect secure-home config path component: {component}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            return component
    return None


def load_config(path: Path) -> SecureHomeConfig | None:
    """Load the secure-home config, or ``None`` if the feature isn't configured.

    Fails closed on anything unexpected — a symlinked path component, an
    irregular file, group/other-accessible permissions, foreign ownership,
    an oversized file, invalid JSON, non-UTF-8 bytes, or a malformed payload
    all raise :class:`SecureHomeConfigError` rather than returning a
    best-effort guess.
    """
    absolute = _resolve_absolute(path)
    symlinked = _first_symlink_component(absolute)
    if symlinked is not None:
        raise SecureHomeConfigError(
            f"refusing to read secure-home config: {symlinked} is a symlink{_symlink_hint(symlinked)}"
        )

    try:
        # O_NONBLOCK: opening a FIFO read-only would otherwise block until a
        # writer appears — the fstat S_ISREG check below refuses it instead.
        fd = os.open(str(absolute), os.O_RDONLY | os.O_NONBLOCK | _O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SecureHomeConfigError(f"could not open secure-home config: {absolute}: {exc}") from exc

    try:
        metadata = os.fstat(fd)
        _check_loaded_file(metadata, absolute)
        data = _read_all(fd)
    except OSError as exc:
        raise SecureHomeConfigError(f"could not read secure-home config: {absolute}: {exc}") from exc
    finally:
        os.close(fd)

    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecureHomeConfigError(f"secure-home config is not valid UTF-8: {absolute}: {exc}") from exc
    return _parse_config(raw, absolute)


def _read_all(fd: int) -> bytes:
    """Loop ``os.read`` to EOF (bounded by the fstat size cap already enforced)."""
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _check_loaded_file(metadata: os.stat_result, path: Path) -> None:
    """Every check runs on the opened descriptor's ``fstat`` — no re-open window."""
    if not stat.S_ISREG(metadata.st_mode):
        raise SecureHomeConfigError(f"secure-home config is not a regular file: {path}")
    if _geteuid is not None and metadata.st_uid != _geteuid():
        raise SecureHomeConfigError(f"secure-home config must be owned by the current user: {path}")
    if metadata.st_mode & 0o077:
        raise SecureHomeConfigError(
            f"secure-home config must not be accessible to group or others (expected mode 0600): {path}"
        )
    if metadata.st_size > _MAX_CONFIG_BYTES:
        raise SecureHomeConfigError(f"secure-home config is implausibly large ({metadata.st_size} bytes): {path}")


def _parse_config(raw: str, path: Path) -> SecureHomeConfig:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SecureHomeConfigError(f"secure-home config is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureHomeConfigError(f"secure-home config must be a JSON object: {path}")

    version = payload.get("version")
    if version != CONFIG_VERSION:
        raise SecureHomeConfigError(
            f"secure-home config version {version!r} is not supported (expected {CONFIG_VERSION}): {path}"
        )

    try:
        mount_point_raw = payload["mount_point"]
        volume_uuid = payload["volume_uuid"]
    except KeyError as exc:
        raise SecureHomeConfigError(f"secure-home config is missing required field {exc}: {path}") from exc
    home_subdir_raw = payload.get("home_subdir", "hermes-home")

    _require_str(mount_point_raw, "mount_point", path)
    _require_str(volume_uuid, "volume_uuid", path)
    _require_str(home_subdir_raw, "home_subdir", path)

    try:
        return SecureHomeConfig(
            version=version,
            mount_point=Path(mount_point_raw),
            volume_uuid=volume_uuid,
            home_subdir=home_subdir_raw,
        )
    except SecureHomeConfigError as exc:
        raise SecureHomeConfigError(f"secure-home config at {path} is invalid: {exc}") from exc


def _require_str(value: Any, field: str, path: Path) -> None:
    if not isinstance(value, str):
        raise SecureHomeConfigError(f"secure-home config field {field!r} must be a string: {path}")


def save_config(config: SecureHomeConfig, path: Path) -> None:
    """Persist *config* atomically, refusing to write through a symlink.

    Creates the parent directory chain if needed — and chmods the leaf to
    ``0o700`` only when this call created it, so pointing
    ``MORDRED_SECURE_HOME_CONFIG`` into a pre-existing directory does not
    silently narrow a directory we do not own. The payload goes through a
    same-directory temp file at mode ``0o600`` and is ``os.replace``d into
    place — a reader can never observe a partially-written config.
    """
    absolute = _resolve_absolute(path)
    symlinked = _first_symlink_component(absolute)
    if symlinked is not None:
        raise SecureHomeConfigError(
            f"refusing to write secure-home config: {symlinked} is a symlink{_symlink_hint(symlinked)}"
        )

    directory = absolute.parent
    directory_created = not directory.exists()
    directory.mkdir(parents=True, exist_ok=True)
    if directory_created:
        os.chmod(directory, _DIR_MODE)

    data = _serialize(config)
    tmp_path = directory / f".{absolute.name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW)
    try:
        try:
            os.fchmod(fd, _FILE_MODE)
            _write_all(fd, data)
        finally:
            os.close(fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        raise
    os.replace(tmp_path, absolute)


def _serialize(config: SecureHomeConfig) -> bytes:
    payload = {
        "version": config.version,
        "mount_point": str(config.mount_point),
        "volume_uuid": config.volume_uuid,
        "home_subdir": config.home_subdir,
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_all(fd: int, data: bytes) -> None:
    """Loop ``os.write`` to completion — a short write must never commit a truncated file."""
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("os.write returned 0 bytes while saving secure-home config")
        offset += written
