"""``hermes-mordred secure-home {status,adopt,run}`` — Phase 1 CLI layer.

``secure-home`` relocates the *entire* active Hermes home onto a
user-mounted, user-created encrypted APFS volume — a second key layer
underneath FileVault (SPEC.md "Secure home — encrypted-APFS HERMES_HOME").
This module owns only the CLI verbs; the identity chain and the on-disk
pointer format live in :mod:`._secure_home_probe` and
:mod:`._secure_home_paths` respectively, and every check here is a thin
orchestration over their public API — no new verification logic is
introduced at this layer.

Phase 1 performs **zero volume operations**: ``adopt`` never mounts,
creates, or unmounts a volume (the operator does that by hand), and ``run``
never creates anything at the configured mountpoint. The only filesystem
write ``adopt`` performs is the ``<mount>/hermes-home`` directory *inside*
an already-verified mounted volume — created through a directory descriptor
of the mountpoint that is opened only after verification and held across the
``mkdir``, so an eject race cannot land the directory on the underlying
filesystem.

``status`` renders on every platform (reporting the limitation);
``adopt``/``run`` refuse outright off macOS because the identity chain is
built on ``diskutil``/``fdesetup``, which do not exist elsewhere.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn

from . import _term
from ._secure_home_paths import (
    CONFIG_VERSION,
    SecureHomeConfig,
    SecureHomeConfigError,
    load_config,
    resolve_config_path,
    save_config,
)
from ._secure_home_probe import (
    DEFAULT_RUNNER,
    NOT_MOUNTED,
    FileVaultState,
    SecureHomeVerificationError,
    SubprocessRunner,
    ensure_volume_acceptable,
    filevault_status,
    inspect_mounted_volume,
    verify_home,
)

__all__ = [
    "SecureHomeStatusReport",
    "adopt",
    "cli_adopt",
    "cli_run",
    "cli_status",
    "collect",
    "render_json",
    "render_text",
    "run_command",
    "status",
]

_DARWIN = "darwin"
_O_DIRECTORY: Final[int] = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)

# Inherited environment variables that would silently defeat the guarantee
# `run` just verified: the *_STORE overrides relocate native-key blobs to a
# path outside the secure home, and HERMES_SAFE_MODE disables memory sealing
# in the child. Refusing (rather than silently scrubbing) tells the operator
# their environment is poisoned instead of hiding it.
_REFUSED_ENV_VARS: Final[tuple[str, ...]] = (
    "MORDRED_SEKEY_STORE",
    "MORDRED_TPMKEY_STORE",
    "HERMES_SAFE_MODE",
)


# -----------------------------------------------------------------------------
# Shared helpers
# -----------------------------------------------------------------------------
def _to_absolute(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def _load_config_safe(config_path: Path) -> tuple[SecureHomeConfig | None, str | None]:
    """Load the secure-home config, capturing a load failure as text rather than raising."""
    try:
        return load_config(config_path), None
    except SecureHomeConfigError as exc:
        return None, str(exc)


def _refuse_not_macos(verb: str) -> None:
    _term.emit_error(
        f"secure-home {verb}: macOS only — volume identity checks use diskutil/fdesetup, "
        "which are not available on this OS."
    )


# -----------------------------------------------------------------------------
# STATUS
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class SecureHomeStatusReport:
    """Aggregated, side-effect-free snapshot of secure-home state."""

    platform_supported: bool
    configured: bool
    config_path: str
    config_error: str | None
    filevault: str
    mount_point: str | None
    volume_uuid: str | None
    home_path: str | None
    mounted: bool | None
    verified: bool | None
    verification_code: str | None
    verification_error: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "platform_supported": self.platform_supported,
            "configured": self.configured,
            "config_path": self.config_path,
            "config_error": self.config_error,
            "filevault": self.filevault,
            "mount_point": self.mount_point,
            "volume_uuid": self.volume_uuid,
            "home_path": self.home_path,
            "mounted": self.mounted,
            "verified": self.verified,
            "verification_code": self.verification_code,
            "verification_error": self.verification_error,
        }


def _report_unsupported_platform(
    *, config_path: Path, config: SecureHomeConfig | None, config_error: str | None
) -> SecureHomeStatusReport:
    """Non-darwin: report the platform limitation without running any probe."""
    return SecureHomeStatusReport(
        platform_supported=False,
        configured=config is not None,
        config_path=str(config_path),
        config_error=config_error,
        filevault=FileVaultState.UNKNOWN.value,
        mount_point=str(config.mount_point) if config else None,
        volume_uuid=config.volume_uuid if config else None,
        home_path=str(config.home_path) if config else None,
        mounted=None,
        verified=None,
        verification_code=None,
        verification_error=None,
    )


def _report_not_configured(*, config_path: Path, config_error: str | None, filevault: str) -> SecureHomeStatusReport:
    return SecureHomeStatusReport(
        platform_supported=True,
        configured=False,
        config_path=str(config_path),
        config_error=config_error,
        filevault=filevault,
        mount_point=None,
        volume_uuid=None,
        home_path=None,
        mounted=None,
        verified=None,
        verification_code=None,
        verification_error=None,
    )


def _mounted_for_status(mount_point: Path, ismount: Callable[[str], bool]) -> bool | None:
    """Probe the mount state directly for the report — never inferred from a failure code.

    ``verify_home`` refuses on a symlinked mountpoint *before* it ever asks
    whether the path is mounted, so deriving ``mounted`` from the failure
    code would report ``mounted: true`` for a check that never ran.
    """
    try:
        return ismount(str(mount_point))
    except (OSError, ValueError):
        return None


def _verify_for_status(
    config: SecureHomeConfig, *, run: SubprocessRunner, ismount: Callable[[str], bool]
) -> tuple[bool, str | None, str | None]:
    """Run the full verification chain for a status report: (verified, code, message)."""
    try:
        verify_home(config, run=run, ismount=ismount)
    except SecureHomeVerificationError as exc:
        return False, exc.code, exc.message
    return True, None, None


def collect(
    *,
    config_path: Path,
    platform: str,
    run: SubprocessRunner = DEFAULT_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
) -> SecureHomeStatusReport:
    """Aggregate secure-home status. Never raises — every failure mode has a report field."""
    config, config_error = _load_config_safe(config_path)
    if platform != _DARWIN:
        return _report_unsupported_platform(config_path=config_path, config=config, config_error=config_error)

    filevault = filevault_status(run=run).value
    if config is None:
        return _report_not_configured(config_path=config_path, config_error=config_error, filevault=filevault)

    verified, code, message = _verify_for_status(config, run=run, ismount=ismount)
    return SecureHomeStatusReport(
        platform_supported=True,
        configured=True,
        config_path=str(config_path),
        config_error=None,
        filevault=filevault,
        mount_point=str(config.mount_point),
        volume_uuid=config.volume_uuid,
        home_path=str(config.home_path),
        mounted=_mounted_for_status(config.mount_point, ismount),
        verified=verified,
        verification_code=code,
        verification_error=message,
    )


def _render_configured_lines(report: SecureHomeStatusReport) -> list[str]:
    if report.mounted is None:
        mount_state = "unknown"
    elif report.mounted:
        mount_state = "mounted"
    else:
        mount_state = "not mounted"
    lines = [
        f"  mount point  : {report.mount_point} ({mount_state})",
        f"  volume uuid  : {report.volume_uuid}",
    ]
    if report.verified:
        lines.append("  identity     : verified")
    else:
        lines.append(f"  identity     : FAILED ({report.verification_code}) - {report.verification_error}")
    lines.append(f"  secure home  : {report.home_path}")
    return lines


def _render_hints(report: SecureHomeStatusReport, *, color: bool) -> list[str]:
    if not report.configured:
        return [
            _term.hint("  hint: run `hermes-mordred secure-home adopt <mountpoint>` to set one up.", enabled=color),
            _term.hint(
                "  hint: FileVault alone (Standard) is enough if your threat model is a lost/stolen powered-off Mac.",
                enabled=color,
            ),
        ]
    if report.verified:
        return [
            _term.hint(
                "  note: files stay readable while the volume is mounted; prompts already sent to a "
                "cloud provider are not protected.",
                enabled=color,
            )
        ]
    return []


def render_text(report: SecureHomeStatusReport, *, color: bool = False) -> str:
    lines = [
        _term.heading("Secure home status:", enabled=color),
        f"  config       : {report.config_path}",
    ]
    if report.config_error is not None:
        lines.append(f"  config error : {report.config_error}")
    lines.append(f"  configured   : {'yes' if report.configured else 'no'}")
    lines.append(f"  filevault    : {report.filevault}")
    if not report.platform_supported:
        lines.append("  platform     : unsupported (secure-home is macOS-only; identity checks skipped)")
    elif report.configured:
        lines.extend(_render_configured_lines(report))
    lines.extend(_render_hints(report, color=color))
    return "\n".join(lines)


def render_json(report: SecureHomeStatusReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def status(
    *,
    config_path: Path,
    platform: str,
    run: SubprocessRunner = DEFAULT_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
    as_json: bool = False,
) -> int:
    """Print the secure-home status report. Always returns 0 (read-only).

    Mirrors ``status_cli.status``'s never-raise, always-succeed contract:
    this command is a diagnostic dashboard, not a health gate — a locked or
    misconfigured secure home is reported, not an error exit.
    """
    report = collect(config_path=config_path, platform=platform, run=run, ismount=ismount)
    if as_json:
        print(render_json(report))
    else:
        print(render_text(report, color=_term.should_color(sys.stdout)))
    return 0


def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``secure-home status [--json]`` — resolves production defaults."""
    return status(
        config_path=resolve_config_path(),
        platform=sys.platform,
        as_json=bool(getattr(args, "json", False)),
    )


# -----------------------------------------------------------------------------
# ADOPT
# -----------------------------------------------------------------------------
def _refuse_existing_config(config_path: Path) -> int | None:
    """Refuse when adopting would silently replace an existing config. ``None`` => clear to proceed."""
    existing, load_error = _load_config_safe(config_path)
    if existing is not None:
        _term.emit_error(
            f"secure-home is already configured for {existing.mount_point} (volume {existing.volume_uuid}); "
            "re-run with --force to replace it"
        )
        return 1
    if load_error is not None:
        _term.emit_error(load_error)
        _term.emit_error("re-run with --force to replace the unreadable config")
        return 1
    return None


def _ensure_home_dir(mount_point: Path, home_subdir: str, *, ismount: Callable[[str], bool]) -> bool:
    """Create ``<mount>/<home_subdir>`` at 0700 through a descriptor of the verified mountpoint.

    Returns ``True`` when this call created it. The mountpoint is opened
    ``O_DIRECTORY|O_NOFOLLOW`` and re-checked as still mounted *after* the
    open; the ``mkdir`` then goes through that held descriptor, so a volume
    ejected in the race window either blocks the detach (the open fd pins a
    normal unmount) or fails the fd-relative operation — it can never land a
    plaintext directory on the underlying filesystem. A symlink or non-
    directory planted at the home path is left untouched for ``verify_home``
    to refuse with its own clear message.
    """
    fd = os.open(str(mount_point), os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    try:
        if not ismount(str(mount_point)):
            raise SecureHomeVerificationError(
                NOT_MOUNTED, f"The volume at {mount_point} was unmounted while adopting; nothing was created."
            )
        try:
            os.mkdir(home_subdir, mode=0o700, dir_fd=fd)
        except FileExistsError:
            return False
        os.chmod(home_subdir, 0o700, dir_fd=fd)  # umask defense: mkdir's mode alone can be widened by umask
        return True
    finally:
        os.close(fd)


def adopt(
    mount_point: Path,
    *,
    config_path: Path,
    platform: str,
    run: SubprocessRunner = DEFAULT_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
    force: bool = False,
) -> int:
    """Record an already-mounted, user-created encrypted APFS volume as the secure home.

    Performs zero volume operations — never mounts or unmounts anything.
    Every identity check fails closed and runs *before* the only write to
    the volume; the config is only written once :func:`verify_home` confirms
    the freshly built config actually holds.
    """
    if platform != _DARWIN:
        _refuse_not_macos("adopt")
        return 1

    mount_point = _to_absolute(mount_point)
    if not force:
        refusal = _refuse_existing_config(config_path)
        if refusal is not None:
            return refusal

    try:
        info = inspect_mounted_volume(mount_point, run=run, ismount=ismount)
        ensure_volume_acceptable(info, mount_point, run=run)
    except SecureHomeVerificationError as exc:
        if exc.code == NOT_MOUNTED:
            _term.emit_error(
                f"{mount_point} is not a mounted volume. secure-home adopt never mounts a volume — "
                "mount the encrypted volume yourself first, then retry."
            )
        else:
            _term.emit_error(exc.message)
        return 1
    if not info.volume_uuid:
        _term.emit_error(f"the volume mounted at {mount_point} did not report a VolumeUUID.")
        return 1

    config = SecureHomeConfig(version=CONFIG_VERSION, mount_point=mount_point, volume_uuid=info.volume_uuid)
    created_home = False
    try:
        created_home = _ensure_home_dir(mount_point, config.home_subdir, ismount=ismount)
        verified = verify_home(config, run=run, ismount=ismount)
        save_config(config, config_path)
    except (SecureHomeVerificationError, SecureHomeConfigError, OSError) as exc:
        message = exc.message if isinstance(exc, SecureHomeVerificationError) else str(exc)
        _term.emit_error(message)
        if created_home:
            with contextlib.suppress(OSError):
                os.rmdir(config.home_path)  # rmdir only removes an empty dir — safe rollback
        return 1

    color = _term.should_color(sys.stdout)
    print("Secure home adopted.")
    print(f"  mount point : {verified.mount_point}")
    print(f"  volume uuid : {verified.volume_uuid}")
    print(f"  secure home : {verified.home}")
    print(_term.hint("Next: hermes-mordred secure-home run -- hermes", enabled=color))
    return 0


def cli_adopt(args: argparse.Namespace) -> int:
    """argparse handler for ``secure-home adopt <mountpoint> [--force]``."""
    return adopt(
        Path(args.mountpoint),
        config_path=resolve_config_path(),
        platform=sys.platform,
        force=bool(getattr(args, "force", False)),
    )


# -----------------------------------------------------------------------------
# RUN
# -----------------------------------------------------------------------------
def _strip_leading_separator(command: Sequence[str]) -> list[str]:
    """Drop one leading ``"--"`` — argparse's ``REMAINDER`` keeps it verbatim."""
    values = list(command)
    if values[:1] == ["--"]:
        return values[1:]
    return values


def _poisoned_env_vars(environ: Mapping[str, str]) -> list[str]:
    return [name for name in _REFUSED_ENV_VARS if environ.get(name, "").strip()]


def run_command(
    command: Sequence[str],
    *,
    config_path: Path,
    platform: str,
    run: SubprocessRunner = DEFAULT_RUNNER,
    ismount: Callable[[str], bool] = os.path.ismount,
    exec_fn: Callable[..., NoReturn] = os.execvpe,
    environ: Mapping[str, str] = os.environ,
    which: Callable[..., str | None] = shutil.which,
) -> int:
    """Fail-closed launcher: verify the secure home, then exec *command* under it.

    Never creates anything at the configured mountpoint — only ``adopt``
    does that. A locked or misidentified volume refuses before
    ``HERMES_HOME`` is ever touched, and a parent environment carrying
    key-material overrides refuses before anything launches.
    """
    if platform != _DARWIN:
        _refuse_not_macos("run")
        return 1

    argv = _strip_leading_separator(command)
    if not argv:
        _term.emit_error("secure-home run requires a command: hermes-mordred secure-home run -- <command...>")
        return 2

    poisoned = _poisoned_env_vars(environ)
    if poisoned:
        _term.emit_error(
            f"refusing to launch: {', '.join(poisoned)} is set in the environment and would "
            "redirect Hermes key material or disable sealing outside the secure home; unset it and retry."
        )
        return 1

    config, config_error = _load_config_safe(config_path)
    if config_error is not None:
        _term.emit_error(config_error)
        return 1
    if config is None:
        _term.emit_error("Secure home is not configured. Run 'hermes-mordred secure-home adopt <mountpoint>' first.")
        return 1

    try:
        verified = verify_home(config, run=run, ismount=ismount)
    except SecureHomeVerificationError as exc:
        _term.emit_error(exc.message)
        return 1

    child_env = dict(environ)
    child_env["HERMES_HOME"] = str(verified.home)
    resolved = which(argv[0], path=child_env.get("PATH", os.defpath))
    if resolved is None:
        _term.emit_error(f"command not found: {argv[0]}")
        return 127
    try:
        exec_fn(resolved, argv, child_env)
    except FileNotFoundError:
        _term.emit_error(f"command not found: {argv[0]}")
        return 127
    except PermissionError:
        _term.emit_error(f"command not executable: {argv[0]}")
        return 126
    return 0


def cli_run(args: argparse.Namespace) -> int:
    """argparse handler for ``secure-home run -- <command...>``."""
    return run_command(
        args.command,
        config_path=resolve_config_path(),
        platform=sys.platform,
    )
