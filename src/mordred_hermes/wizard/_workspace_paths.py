"""On-disk artifact model + resolution for the external ``claude-private`` workspace.

``encryption_cli`` (the ``status`` reader) and ``workspace_cli`` (the
enable/disable/purge verbs) previously hand-copied the same
``CLAUDE_PRIVATE_*`` env resolutions and the mountpoint probe. Sharing them
here keeps the two surfaces pointed at the same artifacts by construction:
``encryption status`` must report exactly the volume / key material the verbs
operate on, and a drifted default (one module honouring an env override the
other missed) would make ``status`` describe a workspace the verbs never
touch.

:class:`WorkspacePaths` is the read-side view (what exists / is mounted);
:class:`WorkspaceEnv` extends it with the key directory the destructive verbs
must also remove. The resolver returns the full :class:`WorkspaceEnv`; a
read-side caller simply ignores ``keydir``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkspacePaths:
    """On-disk locations of the external ``claude-private`` workspace."""

    image: Path  # the encrypted sparsebundle
    blob: Path  # the SE-wrapped passphrase
    mount: Path  # the mountpoint while in-session


@dataclass(frozen=True)
class WorkspaceEnv(WorkspacePaths):
    """:class:`WorkspacePaths` plus the key material directory (removed on purge)."""

    keydir: Path  # holds the wrapped passphrase (removed on purge)


def resolve_workspace_env() -> WorkspaceEnv:
    """Resolve the ``claude-private`` locations from ``CLAUDE_PRIVATE_*`` + HOME defaults.

    Mirrors the external wrapper's own defaults / overrides (see
    ``~/.local/share/claude-private/bin/claude-private``), so the wizard and
    the wrapper agree on where the volume and key material live.
    """
    home = Path(os.path.expanduser("~"))
    image = Path(os.environ.get("CLAUDE_PRIVATE_IMAGE", str(home / "Private" / "claude-private.sparsebundle")))
    keydir = Path(os.environ.get("CLAUDE_PRIVATE_KEYDIR", str(home / ".config" / "claude-private")))
    mount = Path(os.environ.get("CLAUDE_PRIVATE_MOUNT", str(home / ".claude-private-mnt")))
    return WorkspaceEnv(image=image, blob=keydir / "passphrase.wrapped", mount=mount, keydir=keydir)


def is_mountpoint(path: Path) -> bool:
    """Whether ``path`` is currently a mountpoint; never raises (status must not)."""
    try:
        return os.path.ismount(str(path))
    except OSError:
        return False
