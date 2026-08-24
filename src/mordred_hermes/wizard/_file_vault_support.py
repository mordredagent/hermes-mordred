"""Platform availability for the production at-rest file vault.

Pure vault logic remains portable through injected backends and anchor stores.
The shipped anchor store, however, is the macOS login Keychain.  Production
CLI entry points share this helper so they cannot disagree about whether a
file-vault ceremony is runnable on the current host.
"""

from __future__ import annotations

import sys


def production_file_vault_eligibility(platform: str | None = None) -> tuple[bool, str]:
    """Return whether the shipped file-vault anchor exists on ``platform``."""
    platform = sys.platform if platform is None else platform
    if platform == "darwin":
        return True, ""
    return (
        False,
        f"macOS only — no supported production file-vault device-anchor store is available on {platform}",
    )
