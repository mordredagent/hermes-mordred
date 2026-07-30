"""``hermes mordred encryption {enable,disable,purge} workspace`` — Claude workspace.

Wraps the **external** ``claude-private`` tool (a Touch ID / Secure Enclave-gated
encrypted APFS sparsebundle holding the Claude Code workspace) from the unified
encryption surface. macOS-only — the SE/APFS machinery does not exist elsewhere.

Deliberately **never auto-mounts** the volume:

- **enable**  drives ``claude-private-setup`` (build + create the volume + escrow
  the key) when it is not yet set up; guides the operator when the external tool
  is not installed.
- **disable** ``hdiutil detach`` the mount — seals it (encrypted, unreadable).
  Non-destructive and instantly re-mountable; a no-op when already sealed.
- **purge**   removes the sparsebundle + key material. It REFUSES while mounted
  (mid-session) and warns that the contents are destroyed too. It does **not**
  auto-mount to export — unlocking the SE-sealed volume needs a live Touch ID and
  cannot be done safely/headlessly, so the operator exports first (run
  ``claude-private`` and copy out what they need). This keeps the destructive path
  free of an un-testable auto-unlock.

All side effects go through injected ``run`` / ``is_mounted`` / ``tool_on_path``
so the orchestration is unit-tested on any platform.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from . import _term
from ._workspace_paths import WorkspaceEnv
from ._workspace_paths import is_mountpoint as _is_mounted
from ._workspace_paths import resolve_workspace_env as _resolve_env

__all__ = ["WorkspaceEnv", "cli_disable", "cli_enable", "cli_purge", "disable", "enable", "purge"]

_DARWIN = "darwin"
_SETUP_BIN = "claude-private-setup"
_DETACH = "hdiutil"
_WORKSPACE_IMAGE_SUFFIXES = frozenset({".sparsebundle", ".sparseimage", ".dmg", ".img"})
_WORKSPACE_KEY_FILES = frozenset({"passphrase.wrapped", "se.key", "se.pub"})


def _path_entry_exists(path: Path) -> bool:
    """Existence including a dangling symlink directory entry."""
    return path.exists() or path.is_symlink()


def _is_set_up(env: WorkspaceEnv) -> bool:
    """The volume + its wrapped passphrase both exist (mirrors `claude-private` checks)."""
    return env.image.exists() and env.blob.exists()


def _path_component_error(path: Path) -> str | None:
    """Reject symlinks or unreadable metadata anywhere in *path*'s chain."""
    absolute = path if path.is_absolute() else Path.cwd() / path
    for component in (*reversed(absolute.parents), absolute):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return f"could not safely inspect workspace path component: {component}"
        if stat.S_ISLNK(metadata.st_mode):
            return f"workspace purge path contains a symlink component: {component}"
    return None


def _purge_layout_error(env: WorkspaceEnv) -> str | None:
    """Validate path relationships before inspecting artifact contents."""
    raw_paths = (env.image, env.keydir, env.mount, env.blob)
    for path in raw_paths:
        component_error = _path_component_error(path)
        if component_error is not None:
            return component_error

    image = env.image.resolve(strict=False)
    keydir = env.keydir.resolve(strict=False)
    mount = env.mount.resolve(strict=False)
    blob = env.blob.resolve(strict=False)
    if blob != keydir / "passphrase.wrapped":
        return "wrapped-passphrase path is not inside the configured key directory"

    protected = (Path("/"), Path.home().resolve(strict=False), Path.cwd().resolve(strict=False))
    for target in (image, keydir):
        if any(target == item or target in item.parents for item in protected):
            return f"refusing broad workspace purge target: {target}"

    if image == keydir or image in keydir.parents or keydir in image.parents:
        return "workspace image and key directory overlap"
    if image == mount or image in mount.parents or mount in image.parents:
        return "workspace image and mount path overlap"
    if keydir == mount or keydir in mount.parents or mount in keydir.parents:
        return "workspace key directory and mount path overlap"
    return None


def _purge_image_error(image_path: Path) -> str | None:
    """Validate a present image as a supported file or sparsebundle."""
    if not image_path.exists():
        return None
    image = image_path.resolve(strict=False)
    if image.suffix.lower() not in _WORKSPACE_IMAGE_SUFFIXES:
        return f"workspace image has an unexpected suffix: {image}"
    if image_path.is_dir():
        if not (image_path / "Info.plist").is_file() or not (image_path / "bands").is_dir():
            return f"workspace sparsebundle is missing Info.plist/bands: {image}"
    elif not image_path.is_file():
        return f"workspace image is not a regular file or sparsebundle: {image}"
    return None


def _purge_keydir_error(keydir_path: Path) -> str | None:
    """Validate a present key directory without following nested objects.

    OS metadata droppings (``.DS_Store`` after a Finder visit, editor swap
    files) are ignored rather than treated as tampering: refusing on them would
    permanently block purge on exactly the platform this feature targets, with a
    message that reads like an attack. The recognized artifacts are still
    required, and any *non-hidden* stranger is still a refusal.
    """
    if not keydir_path.exists():
        return None
    keydir = keydir_path.resolve(strict=False)
    if not keydir_path.is_dir():
        return f"workspace key path is not a directory: {keydir}"
    entries = list(keydir_path.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        return f"workspace key directory contains a non-regular entry: {keydir}"
    names = {entry.name for entry in entries}
    significant = {name for name in names if not name.startswith(".")}
    if not significant & _WORKSPACE_KEY_FILES:
        return f"workspace key directory has no recognizable artifacts: {keydir}"
    unexpected = significant - _WORKSPACE_KEY_FILES
    if unexpected:
        return f"workspace key directory contains unexpected entries: {', '.join(sorted(unexpected))}"
    return None


def _purge_target_error(env: WorkspaceEnv) -> str | None:
    """Return a refusal reason unless the destructive targets look canonical."""
    layout_error = _purge_layout_error(env)
    if layout_error is not None:
        return layout_error
    image_error = _purge_image_error(env.image)
    if image_error is not None:
        return image_error
    return _purge_keydir_error(env.keydir)


def _not_macos(platform: str, verb: str) -> bool:
    if platform != _DARWIN:
        _term.emit_error(
            f"encryption {verb} workspace: macOS only — the Claude workspace volume uses the Secure "
            "Enclave / APFS, which are not available on this OS."
        )
        return True
    return False


def enable(
    *,
    env: WorkspaceEnv,
    platform: str,
    run: Callable[[list[str]], int],
    tool_on_path: Callable[[str], bool],
) -> int:
    """Set up the encrypted workspace (idempotent). Returns 0 / the setup rc, 1 on guard.

    A no-op success when the volume already exists; drives ``claude-private-setup``
    otherwise; rc 1 with guidance when the external tool is not installed.
    """
    if _not_macos(platform, "enable"):
        return 1
    if _is_set_up(env):
        print(f"Claude workspace already set up ({env.image}); nothing to do.")
        return 0
    if not tool_on_path(_SETUP_BIN):
        _term.emit_error(
            f"{_SETUP_BIN!r} is not on PATH — the Claude workspace tool (claude-private) is not installed. "
            "Install it (see ~/.local/share/claude-private), then re-run."
        )
        return 1
    return run([_SETUP_BIN])


def disable(
    *,
    env: WorkspaceEnv,
    platform: str,
    run: Callable[[list[str]], int],
    is_mounted: Callable[[Path], bool],
) -> int:
    """Seal the workspace by detaching the mount. Non-destructive; instantly re-mountable.

    No-op success when not set up or already sealed. Returns 0, the detach rc, or 1
    on the platform guard.
    """
    if _not_macos(platform, "disable"):
        return 1
    if not _is_set_up(env):
        print("Claude workspace is not set up — nothing to seal.")
        return 0
    if not is_mounted(env.mount):
        print(f"Claude workspace already sealed (not mounted at {env.mount}).")
        return 0
    rc = run([_DETACH, "detach", str(env.mount)])
    if rc != 0:
        _term.emit_error(f"failed to detach {env.mount} (rc {rc}) — it may still be mounted.")
        return rc
    print(f"Claude workspace sealed (detached {env.mount}).")
    return 0


def purge(
    *,
    env: WorkspaceEnv,
    platform: str,
    is_mounted: Callable[[Path], bool],
) -> int:
    """Remove the encrypted workspace volume + key material (destructive).

    Refuses while the volume is mounted (mid-session). Does NOT auto-mount/export —
    the operator must export anything they need first (run ``claude-private`` and
    copy it out). Returns 0 on success (an absent volume is a clean no-op), 1 when
    mounted or on the platform guard.
    """
    if _not_macos(platform, "purge"):
        return 1
    if not _path_entry_exists(env.image) and not _path_entry_exists(env.keydir):
        print("Claude workspace is not set up — nothing to purge.")
        return 0
    target_error = _purge_target_error(env)
    if target_error is not None:
        _term.emit_error(f"refusing to purge workspace: {target_error}.")
        return 1
    if is_mounted(env.mount):
        _term.emit_error(
            f"refusing to purge: the Claude workspace is mounted at {env.mount} (mid-session). "
            "Seal it first (`encryption disable workspace`), then retry."
        )
        return 1

    _term.emit_warn(
        "removing the encrypted Claude workspace and ALL its contents (transcripts, settings, "
        "history). This does NOT export them first — if you need that data, cancel, run `claude-private`, "
        f"and copy it out, then retry. Targets: volume={env.image}; key material={env.keydir}."
    )
    image_gone = _remove_path(env.image)
    keydir_gone = _remove_path(env.keydir)
    if not (image_gone and keydir_gone):
        # Never claim a destructive op succeeded when it did not — a residual
        # encrypted volume the operator believes is gone is worse than a clear error.
        _term.emit_error(
            f"failed to fully remove the Claude workspace (image removed={image_gone}, "
            f"keydir removed={keydir_gone}) — remove the leftovers by hand: {env.image}, {env.keydir}."
        )
        return 1
    print(f"Claude workspace purged ({env.image} and {env.keydir} removed).")
    return 0


def _remove_path(path: Path) -> bool:
    """Remove a file or directory tree; return whether it is gone afterward.

    Handles both the default sparsebundle (a directory) and a single-file image,
    and never raises — a removal failure is reported via the return value so the
    destructive caller can fail loudly instead of misreporting success.
    """
    # Re-check immediately before each destructive operation. The initial
    # purge validation may be separated from deletion by a mount probe and
    # terminal output, during which an existing parent could be swapped for a
    # symlink to unrelated data.
    if _path_component_error(path) is not None:
        return False
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.is_symlink() or path.exists():
            path.unlink()
    except OSError:
        pass
    return not _path_entry_exists(path)


# -----------------------------------------------------------------------------
# Production resolution + CLI adapters (wired via encryption_cli dispatch)
# -----------------------------------------------------------------------------
def _run(cmd: list[str]) -> int:
    return subprocess.run(cmd, check=False).returncode


def cli_enable() -> int:
    return enable(
        env=_resolve_env(),
        platform=sys.platform,
        run=_run,
        tool_on_path=lambda name: shutil.which(name) is not None,
    )


def cli_disable() -> int:
    return disable(env=_resolve_env(), platform=sys.platform, run=_run, is_mounted=_is_mounted)


def cli_purge() -> int:
    return purge(env=_resolve_env(), platform=sys.platform, is_mounted=_is_mounted)
