"""``hermes-mordred status`` — the at-a-glance Mordred dashboard.

UX review 2026-06-11: Mordred state was scattered over five read commands
(``network status`` / ``encryption status`` / ``vault status`` /
``keyvault list`` / ``policy show``). This module aggregates the answer
to "how am I protected right now?" into one screen:

- **policy**     — the active policy mode (same source as the install hook).
- **network**    — configured default path, plus live runtime state when one
  is registered in this process.
- **keyvault**   — initialised?, key count, hardware-helper presence.
- **encryption** — the four at-rest targets via
  :func:`mordred_hermes.wizard.encryption_cli.collect_status`.

Side-effect-free by the same contract as ``encryption status``: never
prompts, never opens the vault cold path, never touches the Secure
Enclave or TPM — on-disk reads and PATH lookups only. Heavy imports stay
function-local so the module imports on any platform.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .._home import hermes_home as _hermes_home
from ..keyvault._identity import resolve_root
from . import _term
from .encryption_cli import (
    STATUS_LEGEND_BODY,
    WORKSPACE_LEGEND_BODY,
    TargetStatus,
    WorkspacePaths,
    _default_workspace_paths,
    collect_status,
    status_mark,
    style_mark,
)

__all__ = [
    "StatusReport",
    "cli_status",
    "collect",
    "render_json",
    "render_text",
    "status",
]

#: Resolve the platform hardware-helper binary, or None. Injected in tests.
HelperFinder = Callable[[str], str | None]


@dataclass(frozen=True)
class StatusReport:
    """Aggregated, side-effect-free snapshot of Mordred's protection state."""

    policy_mode: str
    network_configured_path: str
    network_live: bool
    network_active_path: str | None
    network_ready: bool | None
    keyvault_initialized: bool
    keyvault_key_count: int
    keyvault_helper_installed: bool
    keyvault_detail: str
    encryption: list[TargetStatus]

    def to_dict(self) -> dict[str, object]:
        return {
            "policy": {"mode": self.policy_mode},
            "network": {
                "configured_path": self.network_configured_path,
                "live": self.network_live,
                "active_path": self.network_active_path,
                "ready": self.network_ready,
            },
            "keyvault": {
                "initialized": self.keyvault_initialized,
                "key_count": self.keyvault_key_count,
                "helper_installed": self.keyvault_helper_installed,
                "detail": self.keyvault_detail,
            },
            "encryption": [s.to_dict() for s in self.encryption],
        }


# -----------------------------------------------------------------------------
# Section collectors — each reads on-disk state only and never raises.
# -----------------------------------------------------------------------------
def _policy_mode(home: Path) -> str:
    """The active policy mode, from the same source the install hook uses."""
    from ..privacy_check._runtime import get_active_policy_mode

    return str(get_active_policy_mode(config_path=home / "config.yaml"))


def _network_state(home: Path) -> tuple[str, bool, str | None, bool | None]:
    """(configured_path, live, active_path, ready) without bringing anything up."""
    from ..network import api
    from ..network._exceptions import MordredNetworkError
    from .network_cli import _read_default_path_from_config

    configured = _read_default_path_from_config(home / "config.yaml")
    try:
        live_status = api.status()
    except MordredNetworkError:
        return configured, False, None, None
    return configured, True, live_status.active_path, live_status.ready


def _keyvault_state(home: Path) -> tuple[bool, int, str]:
    """(initialized, key_count, detail) from meta.json — no backend, no prompt."""
    from ..keyvault import _storage

    root = _storage.resolve_keyvault_dir(home)
    try:
        meta = _storage.load_meta(root)
    except _storage.KeyvaultCorruptError as exc:
        return False, 0, f"meta.json corrupt — {exc}"
    except OSError as exc:  # KeyvaultPermissionError (bad mode / not a regular file)
        return False, 0, f"keyvault unreadable — {exc}"
    count = len(meta.get("keys", {}))
    if count == 0:
        return False, 0, "not initialised"
    return True, count, f"{count} key" + ("" if count == 1 else "s")


def _default_helper_finder(platform: str) -> str | None:
    """Locate the installed hardware-helper binary for this OS (PATH/file lookup only)."""
    from ..keyvault import _seckey_helper

    if platform == "darwin":
        return _seckey_helper._find_helper()
    if platform.startswith("linux"):
        return _seckey_helper.find_tpmkey_helper()
    return None


# -----------------------------------------------------------------------------
# Aggregation + rendering
# -----------------------------------------------------------------------------
def collect(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    on_path: Callable[[str], bool] | None = None,
    helper_finder: HelperFinder | None = None,
) -> StatusReport:
    finder = helper_finder if helper_finder is not None else _default_helper_finder
    # status never raises: the helper lookup walks PATH and the home dir,
    # either of which can blow up in odd environments (e.g. Path.home()
    # RuntimeError in a container with no passwd entry) — degrade to
    # "not installed" instead (review 2026-06-12).
    try:
        helper_installed = finder(platform) is not None
    except Exception:
        helper_installed = False
    configured, live, active_path, ready = _network_state(home)
    kv_initialized, kv_count, kv_detail = _keyvault_state(home)
    return StatusReport(
        policy_mode=_policy_mode(home),
        network_configured_path=configured,
        network_live=live,
        network_active_path=active_path,
        network_ready=ready,
        keyvault_initialized=kv_initialized,
        keyvault_key_count=kv_count,
        keyvault_helper_installed=helper_installed,
        keyvault_detail=kv_detail,
        encryption=collect_status(home=home, root=root, platform=platform, workspace=workspace, on_path=on_path),
    )


def render_text(report: StatusReport, *, color: bool = False) -> str:
    if report.network_live:
        ready = "ready" if report.network_ready else "not ready"
        network = f"{report.network_active_path} (live, {ready})"
    else:
        network = f"{report.network_configured_path} (configured; runtime not active in this process)"
    helper = "hardware helper installed" if report.keyvault_helper_installed else "no hardware helper"
    if report.keyvault_initialized:
        keyvault = f"initialised ({report.keyvault_detail}; {helper})"
    else:
        keyvault = f"{report.keyvault_detail} ({helper})"
    lines = [
        _term.heading("Mordred status:", enabled=color),
        f"  policy mode : {report.policy_mode}",
        f"  network     : {network}",
        f"  keyvault    : {keyvault}",
        "  encryption  :",
    ]
    width = max((len(s.target) for s in report.encryption), default=0)
    marks = [status_mark(s) for s in report.encryption]
    mark_w = max((len(m) for m in marks), default=0)
    for s, mark in zip(report.encryption, marks, strict=True):
        cell = style_mark(mark, mark.ljust(mark_w), enabled=color)
        lines.append(f"    {s.target.ljust(width)}  [{cell}]  {s.detail}")
    if "paused" in marks:
        lines.append(_term.hint(f"    legend: {STATUS_LEGEND_BODY}", enabled=color))
    if "sealed" in marks or "open" in marks:
        lines.append(_term.hint(f"    workspace: {WORKSPACE_LEGEND_BODY}", enabled=color))
    return "\n".join(lines)


def render_json(report: StatusReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def status(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    as_json: bool = False,
    on_path: Callable[[str], bool] | None = None,
    helper_finder: HelperFinder | None = None,
) -> int:
    """Print the aggregated report. Always returns 0 (read-only)."""
    report = collect(
        home=home,
        root=root,
        platform=platform,
        workspace=workspace,
        on_path=on_path,
        helper_finder=helper_finder,
    )
    if as_json:
        print(render_json(report))
    else:
        print(render_text(report, color=_term.should_color(sys.stdout)))
    return 0


# -----------------------------------------------------------------------------
# CLI adapter wired in cli.py
# -----------------------------------------------------------------------------
def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``status [--json]`` — resolves production defaults."""
    home = _hermes_home()
    return status(
        home=home,
        root=resolve_root(None),
        platform=sys.platform,
        workspace=_default_workspace_paths(),
        as_json=bool(getattr(args, "json", False)),
    )
