"""Eligibility of the production file vault's Keychain device anchor.

Dedicated Linux/Windows memory custody does not use this file-vault store.
Injected anchor stores remain portable; callers gate only production defaults.
"""

from __future__ import annotations

import sys


def production_file_vault_eligibility(platform: str | None = None) -> tuple[bool, str]:
    """Whether this host supports the production Keychain anchor, without I/O.

    This is platform eligibility, not a live Keychain/backend readiness probe.
    """
    if (sys.platform if platform is None else platform) == "darwin":
        return True, ""
    return False, "Production file-vault device authentication requires the macOS Keychain anchor."
