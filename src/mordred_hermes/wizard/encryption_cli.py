"""``hermes mordred encryption`` — unified at-rest toggle for four targets.

One consistent command surface to turn on/off the at-rest encryption of:

- ``env``       — ``~/.hermes/.env`` enrolled into the vault (runtime-injected)
- ``config``    — ``~/.hermes/config.yaml`` via the ``.pth`` startup decrypt hook
- ``memory``    — Hermes agent memory (``HERMES_MEMORY_KEY`` + ``config.yaml`` flag)
- ``workspace`` — the external Touch ID/SE Claude Code workspace (``claude-private``)

This module owns the ``status`` reader and the namespace dispatch. ``status`` is
deliberately **side-effect-free**: it never opens the vault cold path (no
passphrase prompt) and never probes the device key store. It reads only on-disk
artifacts —

- enrollment from the *plaintext* manifest body
  (:func:`mordred_hermes.keyvault.manifest.parse_unverified`; the names are
  operational metadata, not secret),
- the config opt-in marker file,
- the ``memory.encryption.enabled`` flag in ``config.yaml``,
- the workspace sparsebundle / wrapped-passphrase / mountpoint.

``active`` is the *effective* state on **this** OS. The runtime decrypt shims are
macOS-only (:mod:`mordred_hermes.keyvault._runtime_env`,
:mod:`mordred_hermes.keyvault._config_bootstrap`), so an enrolled-but-off-darwin
target is reported ``active=False`` rather than implying protection that is not
wired here.

Heavy imports stay function-local so this module imports on any platform, like
the other wizard CLI modules.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .._home import hermes_home as _hermes_home
from ..keyvault._config_bootstrap import _marker_path as _config_marker_path
from ..keyvault._config_bootstrap import config_hook_installed
from ..keyvault._identity import resolve_root
from ..keyvault._runtime_env import _env_optout_marker_path
from . import _term

__all__ = [
    "TARGETS",
    "TargetStatus",
    "WorkspacePaths",
    "cli_status",
    "collect_status",
    "config_status",
    "env_status",
    "memory_status",
    "render_json",
    "render_text",
    "status",
    "status_mark",
    "style_mark",
    "workspace_status",
]

#: The four toggleable targets, in display order.
TARGETS: tuple[str, ...] = ("env", "config", "memory", "workspace")

_CONFIG_NAME = "config.yaml"
_DARWIN = "darwin"


@dataclass(frozen=True)
class TargetStatus:
    """The resolved state of one encryption target.

    - ``configured``: the toggle is on (enrolled / marker present / flag true /
      workspace artifacts on disk), independent of the current OS.
    - ``active``: it is *effectively* protecting data on **this** OS right now.
    - ``mounted``: workspace-only rendering hint — ``True`` when the encrypted
      volume is mounted (open / in use), ``False`` when sealed at rest,
      ``None`` for the non-workspace targets. The workspace is encrypted at
      rest whenever it exists and is *unmounted*, so this sealed-vs-open axis,
      not ``on/paused/off``, is what :func:`status_mark` keys on for it.
    """

    target: str
    configured: bool
    active: bool
    detail: str
    mounted: bool | None = None
    drift: bool = False

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "target": self.target,
            "configured": self.configured,
            "active": self.active,
            "detail": self.detail,
        }
        if self.mounted is not None:
            out["mounted"] = self.mounted
        if self.drift:
            out["drift"] = self.drift
        return out


@dataclass(frozen=True)
class WorkspacePaths:
    """On-disk locations of the external ``claude-private`` workspace."""

    image: Path
    blob: Path
    mount: Path


# -----------------------------------------------------------------------------
# Side-effect-free detection primitives
# -----------------------------------------------------------------------------
def _enrolled_names(root: Path) -> set[str]:
    """Logical names enrolled in the vault at ``root`` — no device key, no cold path.

    Reads the newest ``manifest.<gen>.mvmf`` and parses its *unverified* body. The
    manifest body is plaintext JSON whose ``files`` keys are the enrolled names
    (operational metadata, not secret), so this needs neither the master key nor a
    passphrase. Returns an empty set when there is no vault / no manifest / the
    manifest is unreadable — status must never raise.
    """
    from ..keyvault import manifest, vault

    try:
        generation = vault._latest_manifest_generation(root)
        if generation is None:
            return set()
        blob = vault._manifest_path(root, generation).read_bytes()
        parsed = manifest.parse_unverified(blob)
    except (OSError, manifest.ManifestError):
        return set()
    return set(parsed.files)


def _memory_flag_enabled(home: Path) -> bool:
    """Whether ``config.yaml`` has ``memory.encryption.enabled: true``.

    Side-effect-free read. A missing / unreadable / sealed-away config.yaml is
    treated as not-enabled (the flag is simply not observable here).
    """
    config_path = home / _CONFIG_NAME
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return False

    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    try:
        data = YAML(typ="safe").load(text)
    except YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    memory = data.get("memory")
    encryption = memory.get("encryption") if isinstance(memory, dict) else None
    enabled = encryption.get("enabled") if isinstance(encryption, dict) else None
    return enabled is True


def _os_note(active: bool, platform: str) -> str:
    return "active" if active else f"enrolled; inactive on this OS ({platform})"


# -----------------------------------------------------------------------------
# Per-target detectors
# -----------------------------------------------------------------------------
def env_status(*, root: Path, home: Path, platform: str) -> TargetStatus:
    enrolled = ".env" in _enrolled_names(root)
    opted_out = _env_optout_marker_path(home).exists()
    configured = enrolled
    # The runtime shim skips injection when the opt-out marker is present, so an
    # enrolled-but-opted-out target is NOT active even on macOS.
    active = enrolled and not opted_out and platform == _DARWIN
    # Drift: the sealed state (active) removed the plaintext, so a plaintext on
    # disk means a host write slipped one past the seal — a secret is exposed at
    # rest and the file is partial (it loses the other enrolled keys until
    # resealed). A plaintext is expected (not drift) when opted-out or off-macOS.
    drift = active and (home / ".env").exists()
    if not enrolled:
        detail = "not enrolled"
    elif opted_out:
        detail = "disabled — encrypted copy kept; re-enable: encryption enable env"
    elif drift:
        detail = "plaintext .env present at rest while vault-managed — reseal with: encryption enable env"
    else:
        detail = _os_note(active, platform)
    return TargetStatus("env", configured, active, detail, drift=drift)


def config_status(*, home: Path, platform: str, hook_installed: bool | None = None) -> TargetStatus:
    """Resolve the ``config`` target's status.

    On macOS the data is enrolled, but it is only *effectively* sealed when the
    startup ``.pth`` hook is installed in this runtime — without it the plaintext
    ``config.yaml`` just stays on disk. ``active`` reflects that (the opt-in
    marker alone used to read as "active" even with no hook). ``hook_installed``
    is injectable for tests; production detects it from the live interpreter.
    """
    configured = _config_marker_path(home).exists()
    if not configured:
        return TargetStatus("config", False, False, "not vault-managed")
    if platform != _DARWIN:
        return TargetStatus("config", True, False, "vault-managed; " + _os_note(False, platform))
    hook = config_hook_installed() if hook_installed is None else hook_installed
    if hook:
        return TargetStatus("config", True, True, "vault-managed; decrypt hook installed (sealed on Hermes exit)")
    detail = "vault-managed; decrypt hook NOT installed — plaintext stays on disk (reinstall the mordred-hermes wheel)"
    return TargetStatus("config", True, False, detail)


def memory_status(*, home: Path, platform: str) -> TargetStatus:
    configured = _memory_flag_enabled(home)
    active = configured and platform == _DARWIN
    detail = _os_note(active, platform) if configured else "encryption disabled"
    return TargetStatus("memory", configured, active, detail)


def workspace_status(
    *,
    image: Path,
    blob: Path,
    mount: Path,
    platform: str,
    on_path: Callable[[str], bool] | None = None,
) -> TargetStatus:
    """Detect the external ``claude-private`` workspace from on-disk artifacts.

    ``configured`` = the encrypted volume and its wrapped passphrase both exist.
    ``active`` additionally requires macOS (the SE/APFS protection is macOS-only).
    ``on_path`` resolves whether a helper binary is installed (defaults to
    :func:`shutil.which`); injected in tests.
    """
    if on_path is None:
        import shutil

        def on_path(name: str) -> bool:
            return shutil.which(name) is not None

    configured = image.exists() and blob.exists()
    is_macos = platform == _DARWIN
    active = configured and is_macos
    mounted = _is_mountpoint(mount)
    tools_installed = on_path("claude-private") and on_path("claude-vault-key")

    if not is_macos:
        detail = "macOS only — not available on this OS"
    elif not configured:
        detail = "tools installed; volume not set up" if tools_installed else "not installed"
    elif mounted:
        detail = "unlocked & mounted — in use, not sealed"
    else:
        detail = "sealed at rest — protected, not mounted"
    # `mounted` only carries meaning once the volume is set up on this OS;
    # otherwise the mark is plain `off` and the sealed/open distinction is moot.
    return TargetStatus("workspace", configured, active, detail, mounted=mounted if active else None)


def _is_mountpoint(path: Path) -> bool:
    try:
        return os.path.ismount(str(path))
    except OSError:
        return False


# -----------------------------------------------------------------------------
# Aggregation + rendering
# -----------------------------------------------------------------------------
def collect_status(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    on_path: Callable[[str], bool] | None = None,
) -> list[TargetStatus]:
    return [
        env_status(root=root, home=home, platform=platform),
        config_status(home=home, platform=platform),
        memory_status(home=home, platform=platform),
        workspace_status(
            image=workspace.image,
            blob=workspace.blob,
            mount=workspace.mount,
            platform=platform,
            on_path=on_path,
        ),
    ]


def render_json(statuses: list[TargetStatus]) -> str:
    return json.dumps([s.to_dict() for s in statuses], indent=2)


#: Human-readable meaning of the env/config/memory marks. Shown as a legend
#: under the target list (both renderers) only when a ``paused`` row is present,
#: so the ``paused`` state is never cryptic and an all-on/off list stays clean.
STATUS_LEGEND_BODY = "on = protecting now | paused = set up but off, data kept | off = not set up"

#: Meaning of the workspace-only marks. The workspace runs on a different axis:
#: its volume is encrypted at rest *whenever it is set up and unmounted*, so it
#: never reports ``on``/``paused``. Shown only when a ``sealed`` / ``open`` row
#: is present (see :func:`_workspace_mark`).
WORKSPACE_LEGEND_BODY = "sealed = encrypted & locked at rest | open = mounted, in use | off = not set up here"

#: Meaning of the env-only ``exposed`` mark. Shown only when an ``exposed`` row is
#: present (drift): the target is vault-managed but a plaintext copy is on disk at
#: rest — a host write slipped past the seal. ``encryption enable env`` merges it
#: back into the vault and removes the plaintext.
EXPOSED_LEGEND_BODY = "exposed = vault-managed but a plaintext copy is on disk at rest — reseal: encryption enable env"


def status_mark(status: TargetStatus) -> str:
    """One-word state for the on/off column, keyed on *effective protection*.

    Reflects whether the target is protecting data **right now** (``active``),
    not merely whether it is set up (``configured``) — the prior
    ``configured``-based marker made a disabled-but-still-enrolled ``env`` read
    as ``on``, which is misleading:

    - ``on``     — active: encrypting / protecting on this OS right now.
    - ``paused`` — configured but not active (turned off, or inactive on this
      OS). The encrypted copy is kept, so ``enable`` restores it without
      re-enrolling.
    - ``off``    — not configured: nothing is set up for this target.

    The ``workspace`` target is special-cased onto its own sealed/open/off
    vocabulary by :func:`_workspace_mark`.
    """
    if status.target == "workspace":
        return _workspace_mark(status)
    if status.drift:
        return "exposed"
    if status.active:
        return "on"
    return "paused" if status.configured else "off"


def _workspace_mark(status: TargetStatus) -> str:
    """Workspace mark, keyed on its sealed-vs-mounted axis — not on/paused/off.

    The encrypted volume is protected at rest *whenever it exists and is
    unmounted*, so ``disable`` (which seals it) is the workspace's **most**
    protected state, not its off state. Reusing ``on`` made a freshly-sealed
    workspace read as if ``disable`` had been ignored, which is exactly the
    confusion this avoids:

    - ``sealed`` — set up and unmounted: encrypted & locked at rest (protected).
    - ``open``   — mounted: unlocked and in use this session (not sealed).
    - ``off``    — not set up here (no volume on disk, or not macOS).
    """
    if not status.active:
        return "off"
    return "open" if status.mounted else "sealed"


#: Mark word -> the :mod:`_term` styler that colours it. Shared with
#: ``status_cli`` so the dashboard and the encryption screen colour a mark the
#: same way. ``on``/``sealed`` are protected (green), ``paused`` needs attention
#: (yellow), ``open`` is in-use (cyan), ``off`` is de-emphasised (dim).
_MARK_STYLE: dict[str, Callable[..., str]] = {
    "on": _term.success,
    "sealed": _term.success,
    "paused": _term.warn,
    "open": _term.info,
    "off": _term.dim,
    "exposed": _term.error,
}


def style_mark(mark_word: str, text: str, *, enabled: bool) -> str:
    """Colour *text* by the state *mark_word* names, leaving it unchanged when
    colour is off or the word is unknown.

    *text* is the display cell (often padded), kept separate from the lookup
    *mark_word* so callers can pad first and still colour by state — column
    alignment is preserved because ANSI codes have zero display width.
    """
    if not enabled:
        return text
    styler = _MARK_STYLE.get(mark_word)
    return styler(text, enabled=True) if styler is not None else text


def render_text(statuses: list[TargetStatus], *, color: bool = False) -> str:
    name_w = max(len(s.target) for s in statuses)
    marks = [status_mark(s) for s in statuses]
    # Pad marks to the widest present. With no ``paused`` row the width stays 3
    # (``on``/``off``), so an all-on/off list renders byte-identically to before.
    mark_w = max(len(m) for m in marks)
    lines = [_term.heading("Mordred at-rest encryption:", enabled=color)]
    for s, mark in zip(statuses, marks, strict=True):
        cell = style_mark(mark, mark.ljust(mark_w), enabled=color)
        lines.append(f"  {s.target.ljust(name_w)}  [{cell}]  {s.detail}")
    if "exposed" in marks:
        lines.append(_term.hint(f"  alert: {EXPOSED_LEGEND_BODY}", enabled=color))
    if "paused" in marks:
        lines.append(_term.hint(f"  legend: {STATUS_LEGEND_BODY}", enabled=color))
    if "sealed" in marks or "open" in marks:
        lines.append(_term.hint(f"  workspace: {WORKSPACE_LEGEND_BODY}", enabled=color))
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Default path resolution (production) — overridable in tests
# -----------------------------------------------------------------------------
def _default_workspace_paths() -> WorkspacePaths:
    """Resolve the ``claude-private`` artifact locations from env + HOME defaults.

    Mirrors the external wrapper's own defaults / ``CLAUDE_PRIVATE_*`` overrides
    (see ``~/.local/share/claude-private/bin/claude-private``).
    """
    home = Path(os.path.expanduser("~"))
    image = Path(os.environ.get("CLAUDE_PRIVATE_IMAGE", str(home / "Private" / "claude-private.sparsebundle")))
    keydir = Path(os.environ.get("CLAUDE_PRIVATE_KEYDIR", str(home / ".config" / "claude-private")))
    mount = Path(os.environ.get("CLAUDE_PRIVATE_MOUNT", str(home / ".claude-private-mnt")))
    return WorkspacePaths(image=image, blob=keydir / "passphrase.wrapped", mount=mount)


def status(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    as_json: bool = False,
    on_path: Callable[[str], bool] | None = None,
) -> int:
    """Print the state of all four targets. Always returns 0 (read-only)."""
    statuses = collect_status(home=home, root=root, platform=platform, workspace=workspace, on_path=on_path)
    if as_json:
        print(render_json(statuses))
    else:
        print(render_text(statuses, color=_term.should_color(sys.stdout)))
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py
# -----------------------------------------------------------------------------
def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``encryption status [--json]`` — resolves defaults."""
    home = _hermes_home()
    return status(
        home=home,
        root=resolve_root(None),
        platform=sys.platform,
        workspace=_default_workspace_paths(),
        as_json=bool(getattr(args, "json", False)),
    )


# -----------------------------------------------------------------------------
# enable / disable / purge dispatch — routes a (verb, target) to its engine.
# The encryption surface always uses the default vault root (a custom --root would
# not be seen by the macOS startup shims, which read default_vault_root()).
# -----------------------------------------------------------------------------
def _dispatch(verb: str, target: str) -> int:
    from . import config_decrypt_cli, env_decrypt_cli, memory_cli

    home = _hermes_home()
    root = resolve_root(None)
    platform = sys.platform

    # target -> {verb: action}. enable/disable are explicit; the CLI adapters
    # only ever pass enable/disable/purge, and any non-enable/disable verb
    # resolves to the target's purge (preserves the original if-chain's
    # fall-through). workspace stays lazily imported (macOS-only path).
    routes: dict[str, dict[str, Callable[[], int]]] = {
        "env": {
            "enable": lambda: env_decrypt_cli.enable(home=home, root=root, platform=platform),
            "disable": lambda: env_decrypt_cli.disable(home=home, root=root),
            "purge": lambda: env_decrypt_cli.purge(home=home, root=root),
        },
        "config": {
            "enable": lambda: config_decrypt_cli.enable(home=home, root=root),
            "disable": lambda: config_decrypt_cli.disable(home=home, root=root),
            "purge": lambda: config_decrypt_cli.purge(home=home, root=root),
        },
        "memory": {
            "enable": lambda: memory_cli.enable(home=home, root=root),
            "disable": lambda: memory_cli.disable(home=home),
            "purge": lambda: memory_cli.purge(home=home, root=root),
        },
    }
    if target in routes:
        actions = routes[target]
        return (actions.get(verb) or actions["purge"])()
    if target == "workspace":
        from . import workspace_cli

        ws: dict[str, Callable[[], int]] = {
            "enable": workspace_cli.cli_enable,
            "disable": workspace_cli.cli_disable,
            "purge": workspace_cli.cli_purge,
        }
        return (ws.get(verb) or ws["purge"])()

    _term.emit_error(f"encryption {verb} {target}: not available in this build.")
    return 2


# -----------------------------------------------------------------------------
# `all` pseudo-target — best-effort fan-out of one verb over every target.
# -----------------------------------------------------------------------------
#: Targets an ``all`` fan-out always attempts, in order. Derived from ``TARGETS``
#: (its leading entries) so the two never drift; ``workspace`` is the trailing
#: entry and is handled separately (eligibility-gated) because it is macOS-only
#: and its ``enable`` drives a heavyweight external setup.
_ALL_CORE_TARGETS: tuple[str, ...] = TARGETS[:-1]


def _default_on_path() -> Callable[[str], bool]:
    """Production ``on_path``: is a helper binary resolvable on ``$PATH``?"""
    import shutil

    return lambda name: shutil.which(name) is not None


def _workspace_eligible(
    verb: str,
    *,
    platform: str,
    on_path: Callable[[str], bool],
    workspace: WorkspacePaths | None = None,
) -> tuple[bool, str]:
    """Decide whether an ``all`` fan-out should touch the workspace target.

    Skipping (rather than failing) keeps ``all`` best-effort: the workspace is
    macOS-only and its ``enable`` builds + mounts an external volume, so a Linux
    host or a Mac without the tooling is reported *skipped*, not failed.

    - non-macOS → never eligible.
    - ``enable`` on macOS → eligible only when both helper binaries are present
      (otherwise ``enable`` would just error — tell the user to set it up first).
    - ``disable`` / ``purge`` on macOS → eligible only when the volume is already
      set up (image + wrapped passphrase on disk); else there is nothing to do.
    """
    if platform != _DARWIN:
        return False, "macOS only"
    if verb == "enable":
        if on_path("claude-private") and on_path("claude-vault-key"):
            return True, ""
        return False, "workspace tooling not installed — run `encryption enable workspace` to set it up"
    ws = workspace if workspace is not None else _default_workspace_paths()
    if ws.image.exists() and ws.blob.exists():
        return True, ""
    return False, "workspace not set up"


def _run_target(verb: str, target: str) -> tuple[str, int]:
    """Dispatch one target for an ``all`` fan-out; return ``(status_label, exit_code)``.

    The engine streams its own detail to stdout here; the caller emits the
    one-line per-target status afterwards as a single contiguous summary block.
    """
    rc = _dispatch(verb, target)
    return ("ok" if rc == 0 else f"FAILED (exit {rc})"), rc


def _print_all_summary(verb: str, outcomes: list[tuple[str, str]], *, failed: int, skipped: int) -> None:
    """Print the contiguous result block after all per-target engine output."""
    print(f"encryption {verb} all:")
    for target, status in outcomes:
        print(f"  {target.ljust(9)} {status}")
    ok = len(outcomes) - failed - skipped
    print(f"  {ok} ok, {failed} failed, {skipped} skipped")


def _dispatch_all(
    verb: str,
    *,
    platform: str | None = None,
    on_path: Callable[[str], bool] | None = None,
) -> int:
    """Fan ``verb`` out over every target, best-effort. Returns an exit code.

    Core vault targets (env / config / memory) are always attempted; workspace
    is eligibility-gated (see :func:`_workspace_eligible`) and a skip never
    counts as a failure. Every target runs even if an earlier one failed; the
    exit code is non-zero iff at least one *attempted* target failed. Per-target
    engine output streams inline; the ok/FAILED/skipped roll-up prints once at
    the end as a single block (see :func:`_print_all_summary`).
    """
    platform = sys.platform if platform is None else platform
    on_path = _default_on_path() if on_path is None else on_path

    outcomes: list[tuple[str, str]] = []
    failed = 0
    for target in _ALL_CORE_TARGETS:
        status, rc = _run_target(verb, target)
        outcomes.append((target, status))
        failed += rc != 0

    eligible, reason = _workspace_eligible(verb, platform=platform, on_path=on_path)
    if eligible:
        status, rc = _run_target(verb, "workspace")
        outcomes.append(("workspace", status))
        failed += rc != 0
        skipped = 0
    else:
        outcomes.append(("workspace", f"skipped ({reason})"))
        skipped = 1

    _print_all_summary(verb, outcomes, failed=failed, skipped=skipped)
    return 1 if failed else 0


def cli_enable(args: argparse.Namespace) -> int:
    if args.target == "all":
        return _dispatch_all("enable")
    return _dispatch("enable", args.target)


def cli_disable(args: argparse.Namespace) -> int:
    if args.target == "all":
        return _dispatch_all("disable")
    return _dispatch("disable", args.target)


def cli_purge(args: argparse.Namespace) -> int:
    """``encryption purge <target> --yes`` — destructive; refuse without --yes."""
    if not bool(getattr(args, "yes", False)):
        scope = (
            "ALL encrypted copies (env, config, memory, workspace)" if args.target == "all" else "the encrypted copy"
        )
        _term.emit_error(
            f"encryption purge {args.target} is destructive (removes {scope}). Re-run with --yes to confirm."
        )
        return 2
    if args.target == "all":
        return _dispatch_all("purge")
    return _dispatch("purge", args.target)
