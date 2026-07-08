"""``hermes mordred install <skill>`` -> wizard-side dispatch.

Thin adapter between the argparse handler and
:func:`privacy_check.install_wrapper.run`:

- Pulls the active :class:`PluginState` from the privacy_check runtime cache
  (so policy mode + audit writer always match the live hook surface).
- Translates :class:`InstallBlocked` into ``exit code 2`` plus a
  user-visible stderr line; the underlying audit entry was already written
  by ``install_wrapper.run`` before the raise, so the block event lands
  in ``~/.hermes/mordred/audit.log`` regardless.
- Forwards the install subprocess returncode (0 on success, non-zero on
  installer failure) for allow / warn outcomes so CI scripts can surface
  real install failures.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..privacy_check._keyvault_probe import KeyvaultProbeError
from ..privacy_check._runtime import PluginState, ensure_state
from ..privacy_check.install_wrapper import (
    InstallBlocked,
    SubprocessRunner,
    _default_runner,
)
from ..privacy_check.install_wrapper import (
    run as _wrapper_run,
)
from . import _term


def _ensure_state() -> PluginState:
    """Indirection seam for tests -- production call returns the cached state."""
    return ensure_state()


def run(
    *,
    skill_arg: str,
    state: PluginState,
    runner: SubprocessRunner = _default_runner,
) -> int:
    """Dispatch one install request. Returns the CLI exit code."""
    try:
        result = _wrapper_run(
            skill_path=Path(skill_arg),
            policy_mode=state.policy_mode,
            audit=state.audit,
            runner=runner,
        )
    except InstallBlocked as blocked:
        label = _term.error("blocked:", enabled=_term.should_color(sys.stderr))
        print(f"{label} {blocked.skill_id or '<unknown>'} ({blocked.reason})", file=sys.stderr)
        return 2
    except KeyvaultProbeError as corrupt:
        # The skill declares `requires_keyvault: true` but the keyvault's
        # meta.json is corrupt — report cleanly instead of letting a
        # keyvault-internal traceback escape. Install did not happen, so
        # exit code 2 matches the InstallBlocked path.
        label = _term.error("blocked:", enabled=_term.should_color(sys.stderr))
        print(f"{label} {skill_arg} (keyvault unreadable — {corrupt})", file=sys.stderr)
        return 2
    except OSError as unreadable:
        # A missing / unreadable skill path is an operator error, not a
        # crash — FileNotFoundError otherwise escapes as a raw traceback.
        # Install did not happen, so exit code 2 matches the paths above.
        label = _term.error("error:", enabled=_term.should_color(sys.stderr))
        print(f"{label} cannot read skill at {skill_arg}: {unreadable}", file=sys.stderr)
        return 2
    return result.install_returncode


def cli_handler(args: argparse.Namespace) -> int:
    """argparse adapter wired in :mod:`mordred_hermes.wizard.cli`."""
    state = _ensure_state()
    return run(skill_arg=args.skill, state=state)
