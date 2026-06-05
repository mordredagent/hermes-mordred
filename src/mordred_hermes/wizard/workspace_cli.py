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

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

__all__ = ["WorkspaceEnv", "cli_disable", "cli_enable", "cli_purge", "disable", "enable", "purge"]

_DARWIN = "darwin"
_SETUP_BIN = "claude-private-setup"
_DETACH = "hdiutil"


@dataclass(frozen=True)
class WorkspaceEnv:
    """On-disk locations of the external ``claude-private`` workspace."""

    image: Path  # the encrypted sparsebundle
    blob: Path  # the SE-wrapped passphrase
    mount: Path  # the mountpoint while in-session
    keydir: Path  # holds the wrapped passphrase (removed on purge)


def _is_set_up(env: WorkspaceEnv) -> bool:
    """The volume + its wrapped passphrase both exist (mirrors `claude-private` checks)."""
    return env.image.exists() and env.blob.exists()


def _not_macos(platform: str, verb: str) -> bool:
    if platform != _DARWIN:
        print(
            f"encryption {verb} workspace: macOS only — the Claude workspace volume uses the Secure "
            "Enclave / APFS, which are not available on this OS.",
            file=sys.stderr,
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
        print(
            f"{_SETUP_BIN!r} is not on PATH — the Claude workspace tool (claude-private) is not installed. "
            "Install it (see ~/.local/share/claude-private), then re-run.",
            file=sys.stderr,
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
        print(f"failed to detach {env.mount} (rc {rc}) — it may still be mounted.", file=sys.stderr)
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
    if not _is_set_up(env):
        print("Claude workspace is not set up — nothing to purge.")
        return 0
    if is_mounted(env.mount):
        print(
            f"refusing to purge: the Claude workspace is mounted at {env.mount} (mid-session). "
            "Seal it first (`encryption disable workspace`), then retry.",
            file=sys.stderr,
        )
        return 1

    print(
        "WARNING: removing the encrypted Claude workspace and ALL its contents (transcripts, settings, "
        "history). This does NOT export them first — if you need that data, cancel, run `claude-private`, "
        "and copy it out, then retry.",
        file=sys.stderr,
    )
    image_gone = _remove_path(env.image)
    keydir_gone = _remove_path(env.keydir)
    if not (image_gone and keydir_gone):
        # Never claim a destructive op succeeded when it did not — a residual
        # encrypted volume the operator believes is gone is worse than a clear error.
        print(
            f"failed to fully remove the Claude workspace (image removed={image_gone}, "
            f"keydir removed={keydir_gone}) — remove the leftovers by hand: {env.image}, {env.keydir}.",
            file=sys.stderr,
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
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.is_symlink() or path.exists():
            path.unlink()
    except OSError:
        pass
    return not path.exists()


# -----------------------------------------------------------------------------
# Production resolution + CLI adapters (wired via encryption_cli dispatch)
# -----------------------------------------------------------------------------
def _resolve_env() -> WorkspaceEnv:
    """Resolve the ``claude-private`` locations from ``CLAUDE_PRIVATE_*`` + HOME defaults."""
    home = Path(os.path.expanduser("~"))
    image = Path(os.environ.get("CLAUDE_PRIVATE_IMAGE", str(home / "Private" / "claude-private.sparsebundle")))
    keydir = Path(os.environ.get("CLAUDE_PRIVATE_KEYDIR", str(home / ".config" / "claude-private")))
    mount = Path(os.environ.get("CLAUDE_PRIVATE_MOUNT", str(home / ".claude-private-mnt")))
    return WorkspaceEnv(image=image, blob=keydir / "passphrase.wrapped", mount=mount, keydir=keydir)


def _run(cmd: list[str]) -> int:
    return subprocess.run(cmd, check=False).returncode


def _is_mounted(path: Path) -> bool:
    try:
        return os.path.ismount(str(path))
    except OSError:
        return False


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
