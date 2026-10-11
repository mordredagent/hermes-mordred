"""Telegram requires agent-memory encryption to be on.

Anything the agent remembers about a Telegram conversation lands in
``<home>/memories/*.md``. Hermes writes those files in plaintext unless
Mordred's memory encryption is armed, so every Telegram entry point (login,
sync, listing chats, questions — from the CLI, the browser extension or the
Hermes tools) refuses with ``memory_encryption_required`` until
``hermes-mordred encryption enable memory`` is active and no plaintext
memory file is left on disk.

Windows uses C6's load-only custody and complete checked memory scan. A busy
canonical lock refuses with ``custody_busy`` so callers can retry without an
enrollment or encryption ceremony.
"""

from __future__ import annotations

import sys
from pathlib import Path


class MemoryEncryptionRequired(RuntimeError):
    def __init__(self, code: str = "memory_encryption_required") -> None:
        super().__init__(code)
        self.code = code


def _memory_refusal(home: Path | None) -> str | None:
    """One load-only decision; ``None`` permits, otherwise a stable refusal code."""
    from ..._home import hermes_home
    from ..._private_fs import PrivateFSError

    try:
        selected_home = home or hermes_home()
        if sys.platform == "win32":
            from ..._config_io import CanonicalPaths, canonical_session
            from ...wizard._windows_memory import observe
            from ...wizard._windows_status import memory_target_status

            # Observe's advisory status erases lock classification. Acquire first
            # so transient contention survives, and decide only after clean exit.
            with canonical_session(CanonicalPaths(selected_home), scope="policy", blocking=False):
                status = memory_target_status(observe(selected_home, blocking=False))
        else:
            from ...wizard.encryption_cli import memory_status

            status = memory_status(home=selected_home, platform=sys.platform)
        if bool(status.active) and not bool(status.drift):
            return None
    except PrivateFSError as exc:
        if sys.platform == "win32" and exc.reason == "busy":
            return "custody_busy"
    except Exception:
        pass
    return "memory_encryption_required"


def memory_encryption_active(home: Path | None = None) -> bool:
    """True only when the memory hook is armed and nothing on disk is plaintext."""
    return _memory_refusal(home) is None


def require_memory_encryption(home: Path | None = None) -> None:
    code = _memory_refusal(home)
    if code is not None:
        raise MemoryEncryptionRequired(code)
