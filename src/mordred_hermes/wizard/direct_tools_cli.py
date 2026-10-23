"""``hermes-mordred direct-tools on | off | status`` — Hermes's direct tool calls.

``on`` has Hermes's own ``hermes config set tools.tool_search.enabled off``
write ``<home>/config.yaml`` (Hermes then offers every tool directly instead of
through its ``tool_search`` / ``tool_call`` bridge); ``off`` has ``hermes config
unset`` remove it again. Mordred never edits the file itself. Both print
what changed, the two trade-offs and the restart note; ``status`` prints one
line. A refusal prints ``refused (<code>)`` with a remediation line and exits
1. No other config value is ever printed. The library is
:mod:`.direct_tools`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from . import _term

__all__ = ["cli_direct_tools", "direct_tools_status", "direct_tools_switch"]

RESTART = "Restart Hermes (or Hermes Desktop) for this to take effect."
TRADE_OFFS = {
    True: (
        "Every request now carries the schemas of the tools Hermes used to defer "
        "(about 8,000 more prompt tokens with Mordred's tools), and the model calls them without "
        "tool_search and tool_call.",
        "The setting is Hermes-wide: tools of remote connectors, which Hermes reaches only through "
        "that bridge, are unavailable while it is on.",
    ),
    False: (
        "Hermes defers plugin tools again: prompts are smaller, and the model reaches Mordred's tools "
        "through tool_search and tool_call (one more model round trip per use).",
        "Tools of remote connectors are reachable through that bridge again.",
    ),
}
REMEDIES = {
    "config_unreadable": (
        "Hermes's config.yaml could not be read, is not valid YAML or not a mapping, or its YAML "
        "warns (for example a reused anchor); nothing was changed. Fix or restore it, then try again."
    ),
    "config_vault_managed": (
        "config.yaml is sealed in Mordred's vault and not on disk right now; nothing was changed. "
        "Start Hermes (or Hermes Desktop, then use the Tool calls card on the Mordred page), which "
        "opens config.yaml, or turn the seal off with hermes-mordred encryption disable config."
    ),
    "config_write_failed": (
        "Hermes's `hermes config` command did not finish, or Hermes does not read the setting as asked "
        "afterwards; check config.yaml (hermes config get tools.tool_search.enabled), then try again."
    ),
    "config_has_setting": (
        "config.yaml already sets tools.tool_search to a value Mordred does not replace (only an absent "
        "value, auto, on, true, yes or 1); nothing was changed. Edit config.yaml by hand."
    ),
    "config_unsupported_shape": (
        "config.yaml shares the tools or tool_search mapping with another setting through a YAML "
        "anchor/alias, so changing it would change that setting too; nothing was changed. Edit "
        "config.yaml by hand."
    ),
    "hermes_cli_unsupported": (
        "This Hermes's `hermes config` has no get/unset (hermes-agent before 0.19), so Mordred cannot "
        "change or check the setting; nothing was changed. Such a Hermes may not defer tools at all "
        "(hermes-agent 0.13 has no tool search; Hermes 0.21 is the release that defers every plugin "
        "tool), so the setting may change nothing there. To set it anyway, add these lines to "
        "config.yaml by hand (remove them to turn direct calls off again):"
    ),
    "hermes_cli_missing": (
        "Hermes's own `hermes` command was not found (next to this Python, in "
        "<home>/hermes-agent/venv/bin or as Hermes Desktop's launcher); nothing was changed. "
        "Add these lines to config.yaml by hand (remove them to turn direct calls off again):"
    ),
}


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _state(mode: dict[str, Any]) -> str:
    return "on" if mode["direct"] else "off"


def _refused(code: str) -> int:
    from .direct_tools import SNIPPET

    _term.emit_error(f"direct-tools refused ({code})")
    print(REMEDIES.get(code, REMEDIES["config_write_failed"]), file=sys.stderr)
    if code in ("hermes_cli_missing", "hermes_cli_unsupported"):
        print(SNIPPET, end="", file=sys.stderr)
    return 1


def direct_tools_status(*, home: Path | None = None) -> int:
    """``direct tool calls: on|off (config|default)``; exit 1 when config.yaml cannot be read."""
    from .direct_tools import read_mode

    mode = read_mode(home or _home())
    if mode["direct"] is None:
        return _refused(str(mode.get("code") or "config_unreadable"))
    print(f"direct tool calls: {_state(mode)} ({mode['source']})")
    return 0


def direct_tools_switch(enabled: bool, *, home: Path | None = None) -> int:
    """Turn direct tool calls on or off; print what changed, the trade-offs and the restart note."""
    from .direct_tools import DirectToolsError, read_mode, set_direct

    home = home or _home()
    before = read_mode(home)
    if before["direct"] is None:
        return _refused(str(before.get("code") or "config_unreadable"))
    wanted = "on" if enabled else "off"
    if before["direct"] is enabled:
        print(f"direct tool calls: already {wanted} ({before['source']}); nothing changed.")
        return 0
    try:
        set_direct(home, enabled)
    except DirectToolsError as exc:
        return _refused(exc.code)
    change = (
        "hermes config set tools.tool_search.enabled off"
        if enabled
        else "hermes config unset removed the tools.tool_search setting that made tools direct"
    )
    print(f"direct tool calls: {_state(before)} -> {wanted} ({change}).")
    for sentence in TRADE_OFFS[enabled]:
        print(sentence)
    print(RESTART)
    return 0


def cli_direct_tools(args: argparse.Namespace) -> int:
    command = getattr(args, "direct_tools_command", None)
    if command == "status":
        return direct_tools_status()
    if command in ("on", "off"):
        return direct_tools_switch(command == "on")
    return 2
