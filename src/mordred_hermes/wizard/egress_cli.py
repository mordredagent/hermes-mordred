"""``hermes-mordred egress`` — show and change the tool-egress level.

Levels (see :mod:`mordred_hermes.privacy_check.egress`)::

    lockdown   no internet from tools
    search     web search only                      (default)
    blocklist  everything except blocklisted domains/tools
    off        no restriction

Only ``plugins.mordred_privacy_check.tool_egress`` in ``config.yaml`` is
rewritten (round-trip, comments preserved, under the shared policy write
lock). Hermes picks the change up on the next tool call; no restart needed.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from . import _term

_DESCRIPTIONS = {
    "lockdown": "no internet from tools (local tools and Mordred's Telegram tools only)",
    "search": "web search only; no URL fetching, browsing, remote APIs or arbitrary commands",
    "blocklist": "everything except blocklisted domains and tools",
    "off": "Mordred does not restrict tools",
}


def _config_path() -> Path:
    from .._home import hermes_home

    return hermes_home() / "config.yaml"


def _current_section(path: Path) -> dict[str, Any]:
    from .._yaml_io import load_plugin_section

    section = load_plugin_section(path, "mordred_privacy_check") or {}
    raw = section.get("tool_egress")
    return dict(raw) if isinstance(raw, dict) else {}


def _write_section(path: Path, tool_egress: dict[str, Any]) -> None:
    """Replace only ``plugins.mordred_privacy_check.tool_egress``."""
    from .policy_writer import _atomic_write_text, _policy_write_lock, _read_regular_text, _round_trip_yaml

    with _policy_write_lock(path.parent):
        yaml = _round_trip_yaml()
        text = _read_regular_text(path)
        root = yaml.load(text) if text else None
        if root is None:
            root = {}
        plugins = root.setdefault("plugins", {})
        section = plugins.setdefault("mordred_privacy_check", {})
        section["tool_egress"] = tool_egress
        import io

        buffer = io.StringIO()
        yaml.dump(root, buffer)
        _atomic_write_text(path, buffer.getvalue())


def egress_status(*, config_path: Path | None = None) -> int:
    from ..privacy_check.egress import DEFAULT_BLOCKLIST, load_policy

    path = config_path or _config_path()
    policy = load_policy(path)
    print(f"Tool egress level: {policy.level} — {_DESCRIPTIONS[policy.level]}")
    print(f"Taint (lockdown after private data is read): {'on' if policy.taint else 'off'}")
    extra = [d for d in policy.blocklist if d not in DEFAULT_BLOCKLIST]
    print(f"Blocklist: {len(DEFAULT_BLOCKLIST)} built-in domain(s)" + (f" + {', '.join(extra)}" if extra else ""))
    if policy.blocked_tools:
        print(f"Blocked tools: {', '.join(sorted(policy.blocked_tools))}")
    return 0


def egress_set(level: str, *, config_path: Path | None = None) -> int:
    from ..privacy_check.egress import LEVELS

    if level not in LEVELS:
        _term.emit_error(f"level must be one of: {', '.join(LEVELS)}")
        return 1
    path = config_path or _config_path()
    section = _current_section(path)
    section["level"] = level
    _write_section(path, section)
    print(f"Tool egress level set to {level}: {_DESCRIPTIONS[level]}.")
    return 0


def egress_list_edit(key: str, value: str, *, add: bool, config_path: Path | None = None) -> int:
    path = config_path or _config_path()
    section = _current_section(path)
    items = [str(v) for v in section.get(key, []) if isinstance(v, str | int)]
    value = value.strip().casefold() if key == "blocklist" else value.strip()
    if not value:
        _term.emit_error("a value is required.")
        return 1
    if add and value not in items:
        items.append(value)
    if not add:
        items = [v for v in items if v != value]
    section[key] = items
    _write_section(path, section)
    print(f"{'Added' if add else 'Removed'} {value} {'to' if add else 'from'} {key}.")
    return 0


def egress_taint(enabled: bool, *, config_path: Path | None = None) -> int:
    path = config_path or _config_path()
    section = _current_section(path)
    section["taint"] = enabled
    _write_section(path, section)
    print(f"Taint {'enabled' if enabled else 'disabled'}.")
    return 0


def cli_egress(args: argparse.Namespace) -> int:
    command = getattr(args, "egress_command", None)
    if command == "status":
        return egress_status()
    if command == "set":
        return egress_set(args.level)
    if command in ("block", "unblock"):
        return egress_list_edit("blocklist", args.domain, add=command == "block")
    if command in ("block-tool", "unblock-tool"):
        return egress_list_edit("blocked_tools", args.tool, add=command == "block-tool")
    if command == "taint":
        return egress_taint(args.state == "on")
    return 2


__all__ = ["cli_egress", "egress_list_edit", "egress_set", "egress_status", "egress_taint"]
