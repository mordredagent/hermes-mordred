"""``hermes mordred encryption`` — unified at-rest toggle for four targets.

One consistent command surface to turn on/off the at-rest encryption of:

- ``env``       — ``~/.hermes/.env`` enrolled into the vault (runtime-injected)
- ``config``    — ``~/.hermes/config.yaml`` via the ``.pth`` startup decrypt hook
- ``memory``    — ``~/.hermes/memories/*.md`` sealed by Mordred's memory hook
  (:mod:`mordred_hermes.keyvault._memory_hook`), keyed by ``HERMES_MEMORY_KEY``
- ``workspace`` — the external Touch ID/SE Claude Code workspace (``claude-private``)

This module owns the ``status`` reader and the namespace dispatch. ``status`` is
deliberately **side-effect-free**: it never opens the vault cold path (no
passphrase prompt) and never probes the device key store. It reads only on-disk
artifacts —

- enrollment from the *plaintext* manifest body
  (:func:`mordred_hermes.keyvault.manifest.parse_unverified`; the names are
  operational metadata, not secret),
- the config opt-in marker file,
- the memory opt-in / opt-out markers plus the first bytes of each
  ``<home>/memories/*.md`` (sealed or plaintext — no key needed),
- the workspace sparsebundle / wrapped-passphrase / mountpoint.

The one deliberate exception is :func:`gateway_runtime_lines`, appended to the
text output on macOS: it inspects the process table for a running
``hermes gateway`` and probes that interpreter's decrypt shims in a subprocess.
It still opens no vault and prompts for nothing, and it is skipped entirely for
``--json``.

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
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .._home import hermes_home as _hermes_home
from ..keyvault._config_bootstrap import _marker_path as _config_marker_path
from ..keyvault._config_bootstrap import config_hook_installed
from ..keyvault._identity import resolve_root
from ..keyvault._memory_hook import memory_marker_path, memory_optout_marker_path
from ..keyvault._runtime_env import _env_optout_marker_path
from . import _term
from ._defaults import is_missing_keyvault_stack
from ._file_vault_support import file_vault_plaintext_warning, production_file_vault_eligibility
from ._workspace_paths import WorkspacePaths, resolve_workspace_env
from ._workspace_paths import is_mountpoint as _is_mountpoint

__all__ = [
    "TARGETS",
    "TargetStatus",
    "WorkspacePaths",
    "cli_status",
    "collect_status",
    "config_status",
    "env_status",
    "gateway_runtime_lines",
    "memory_runtime_available",
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
_MEMORIES_DIR = "memories"
#: Enough of a file to answer "does this even start with the magic line?": the
#: magic line plus room for the BOM and leading whitespace it tolerates. A
#: *quick-reject* optimisation only — the deciding classification always runs
#: ``is_sealed`` on the whole file, never on this truncated head (see
#: :func:`_unsealed_memory_files`).
_SEAL_PROBE_BYTES = 64


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
    try:
        from ..keyvault import manifest, vault
    except ModuleNotFoundError as exc:
        # Minimal install (no ``[keyvault]`` extra): ``keyvault.vault`` pulls the
        # crypto stack (argon2 / cryptography / blake3) at import. Nothing can be
        # enrolled without it, so degrade to "nothing enrolled" rather than let
        # ``status`` — an overview command — abort. A genuinely unrelated missing
        # module still propagates (real bug, keeps its traceback).
        if is_missing_keyvault_stack(exc):
            return set()
        raise

    try:
        generation = vault._latest_manifest_generation(root)
        if generation is None:
            return set()
        blob = vault._manifest_path(root, generation).read_bytes()
        parsed = manifest.parse_unverified(blob)
    except (OSError, manifest.ManifestError):
        return set()
    return set(parsed.files)


def _env_target_ready(*, home: Path, root: Path) -> bool:
    """Whether the ``env`` target is enrolled and actually injecting.

    ``.env`` enrolled and not opted out — the state agent-memory encryption
    rides on to get ``HERMES_MEMORY_KEY`` to the runtime (see
    :mod:`mordred_hermes.wizard.memory_cli`'s module docstring): the key is
    carried by the ``.env`` injection shim, so it does not matter that the
    manifest still lists ``.env`` as enrolled if the opt-out marker has
    suppressed the shim. Shared by ``memory_cli._enable_gate_reason`` and
    ``setup_cli``'s memory step so the two do not drift on what "the env
    target is ready" means.
    """
    return ".env" in _enrolled_names(root) and not _env_optout_marker_path(home).exists()


def _memory_file_paths(home: Path) -> list[Path]:
    """Every agent-memory file the hook seals, sorted.

    The live ``<home>/memories/*.md`` plus upstream's ``*.md.bak.<ts>`` drift
    snapshots: those hold the same content, written by upstream's own
    ``write_text``, so migration and drift detection must both cover them.

    Symlinks are never followed: ``is_file()`` alone follows a link to
    classify it, which would let a planted symlink under ``memories/`` have
    its target read, sealed into the store, and the link itself destroyed by
    the atomic-replace writer. Excluding ``is_symlink()`` entries here is the
    primary guard; ``memory_cli``'s sealer/unsealer re-check it too (defence
    in depth against a link swapped in after this scan).
    """
    memories = home / _MEMORIES_DIR
    if not memories.is_dir():
        return []
    return sorted(
        {p for pattern in ("*.md", "*.md.bak.*") for p in memories.glob(pattern) if p.is_file() and not p.is_symlink()}
    )


def _unsealed_memory_files(home: Path) -> list[Path]:
    """Memory files that are plaintext at rest right now.

    Classification only — no key, no decryption. Reads the WHOLE file before
    calling ``is_sealed`` (memory files are small): classifying off a fixed
    ``_SEAL_PROBE_BYTES`` head made the base64 body's alignment a matter of
    luck across file lengths — a truncated body that happened to still look
    structurally valid read as sealed, one that didn't read as plaintext, so a
    real sealed file could misclassify as plaintext and let ``disable`` report
    success without decrypting it, then ``purge`` strip the key out from under
    it (permanent data loss). The head is still read first as a cheap,
    *prefix-only* reject (:func:`~..keyvault.memory_crypto.looks_like_magic_line`,
    never the full ``is_sealed``): a file that does not even start with the
    magic line cannot be sealed, so the common plaintext case skips the full
    read. A file that cannot be read counts as *not* plaintext: an unreadable
    file is no evidence of exposure, and ``status`` must never raise.
    """
    from ..keyvault.memory_crypto import is_sealed, looks_like_magic_line

    plaintext = []
    for path in _memory_file_paths(home):
        try:
            with path.open("rb") as fh:
                head = fh.read(_SEAL_PROBE_BYTES)
                if not looks_like_magic_line(head.decode("utf-8", "surrogateescape")):
                    plaintext.append(path)
                    continue
                data = head + fh.read()
        except OSError:
            continue
        if not is_sealed(data):
            plaintext.append(path)
    return plaintext


def _memory_flag_enabled(home: Path) -> bool:
    """Whether ``config.yaml`` has the legacy ``memory.encryption.enabled: true``.

    Side-effect-free read. A missing / unreadable / sealed-away config.yaml is
    treated as not-enabled (the flag is simply not observable here). The flag is
    **legacy**: no runtime reads it (the marker arms the hook), and it is
    reported only so a profile carrying it is not silently ignored.
    """
    from .._yaml_io import load_yaml_mapping

    data = load_yaml_mapping(home / _CONFIG_NAME)
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
    # Also catch a reseal temp stranded by a crash — a 0o600 plaintext at rest the
    # plain ".env" check would miss; treat it as the same exposed/drift state.
    from .env_decrypt_cli import _RESEAL_TMP_NAME

    stray_plaintext = (home / ".env").exists() or (home / _RESEAL_TMP_NAME).exists()
    drift = active and stray_plaintext
    if not enrolled:
        detail = "not enrolled"
    elif opted_out:
        detail = "disabled — encrypted copy kept; re-enable: encryption enable env"
    elif drift:
        detail = "a plaintext .env copy is on disk at rest while vault-managed — reseal with: encryption enable env"
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
    detail = "vault-managed; decrypt hook NOT installed — plaintext stays on disk (reinstall the hermes-mordred wheel)"
    return TargetStatus("config", True, False, detail)


def memory_runtime_available() -> tuple[bool, str]:
    """Whether **this** interpreter's Hermes has a memory seam Mordred can wrap.

    The in-process half of the capability question, cheap enough for ``status``:
    it classifies the installed ``tools.memory_tool`` by signature (see
    :func:`mordred_hermes.keyvault._memory_hook.seam_check`). The
    cross-interpreter half — can the runtime that actually runs ``hermes``, or a
    gateway running right now, open sealed files? — is answered by
    ``runtime_memory_encryption_available`` at enable time and in
    :func:`gateway_runtime_lines`.

    Fail-closed and total: any import or classification failure is reported as
    unavailable, never raised, because both callers are read-only surfaces.
    """
    try:
        from ..keyvault._memory_hook import seam_check

        return seam_check()
    except Exception as exc:
        # Broad on purpose: `status` must never raise, and an unavailable
        # runtime is exactly what an unexpected failure here means.
        return False, f"the memory-encryption hook is unusable here: {exc!r}"


def memory_status(*, home: Path, platform: str) -> TargetStatus:
    """Resolve the ``memory`` target from the Mordred markers and the files on disk.

    ``<home>/mordred/memory-vault.marker`` is what arms the hook, so it — not
    the legacy ``memory.encryption.enabled`` config key — decides ``configured``.
    ``drift`` is a plaintext memory file sitting next to sealed ones while the
    hook is armed (an out-of-process writer, or a migration that could not
    finish): the data is exposed at rest right now, so it renders ``exposed``.
    """
    marker = memory_marker_path(home).exists()
    optout = memory_optout_marker_path(home).exists()
    available, reason = memory_runtime_available()
    configured = marker or optout
    active = marker and not optout and available and platform == _DARWIN
    drift = marker and not optout and bool(_unsealed_memory_files(home))

    if not configured:
        detail = (
            "legacy config flag set, nothing sealed — run: encryption enable memory"
            if _memory_flag_enabled(home)
            else "not enabled"
        )
    elif optout:
        detail = "disabled — memories are plaintext; re-enable: encryption enable memory"
    elif not available:
        detail = f"enabled, but {reason} — memories written by this runtime are plaintext"
    elif drift:
        detail = "enabled, but a plaintext memory file is on disk — reseal with: encryption enable memory"
    elif platform != _DARWIN:
        detail = _os_note(False, platform)
    else:
        detail = "sealed memory files; hook armed"
    return TargetStatus("memory", configured, active, detail, drift=drift)


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

#: Meaning of the ``exposed`` mark. Shown only when an ``exposed`` row is present
#: (drift): the target is protected, yet a plaintext copy is on disk at rest — a
#: host write slipped past the ``.env`` seal, or a memory file was written by a
#: process without the hook. Re-running that target's ``enable`` reconciles it.
#: Target-neutral wording: both ``env`` and ``memory`` can report ``exposed``.
EXPOSED_LEGEND_BODY = (
    "exposed = protected target has a plaintext copy on disk at rest — reseal: encryption enable <target>"
)


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

    Delegates to :func:`._workspace_paths.resolve_workspace_env` — the same
    resolver the enable/disable/purge verbs use — so ``status`` reports exactly
    the artifacts those verbs operate on.
    """
    return resolve_workspace_env()


def _shim_mark(ok: bool) -> str:
    return "ok" if ok else "MISSING"


def gateway_runtime_lines(*, home: Path, platform: str) -> list[str]:
    """One line per interpreter currently running a ``hermes gateway``.

    ``gateway runtime: <python> (pid N) — env shim: ok | config hook: MISSING | memory hook: ok``

    The three seals are only as good as the interpreter that actually serves the
    gateway: on 2026-06-25 a gateway running from a repo ``.venv`` without
    mordred could not unseal files the seal had removed, while the *expected*
    runtime looked healthy. This makes that interpreter visible before anything
    is sealed.

    Unlike the rest of ``status`` this spends three short subprocess probes per
    discovered gateway (macOS only, and only when one is actually running). No
    probe opens the vault or prompts for Touch ID — the config probe runs with
    the ``.pth`` hook neutralized. Any failure yields no lines: ``status`` must
    never raise or block.
    """
    if platform != _DARWIN:
        return []
    try:
        from ..keyvault._runtime_probe import (
            discover_running_gateway_runtimes,
            runtime_config_decrypt_available,
            runtime_env_injection_available,
            runtime_memory_encryption_available,
        )

        lines = []
        for gateway in discover_running_gateway_runtimes(home=home):
            env_ok, _ = runtime_env_injection_available(home=home, runtime_python=gateway.python)
            config_ok, _ = runtime_config_decrypt_available(home=home, runtime_python=gateway.python)
            memory_ok, _ = runtime_memory_encryption_available(home=home, runtime_python=gateway.python)
            where = f"{gateway.python}" + (f" (pid {gateway.pid})" if gateway.pid is not None else "")
            lines.append(
                f"  gateway runtime: {where} — env shim: {_shim_mark(env_ok)} "
                f"| config hook: {_shim_mark(config_ok)} | memory hook: {_shim_mark(memory_ok)}"
            )
        return lines
    except Exception:
        # Broad on purpose: a diagnostic line must never make `status` fail.
        return []


def status(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    as_json: bool = False,
    on_path: Callable[[str], bool] | None = None,
) -> int:
    """Print the state of all four targets. Always returns 0 (read-only).

    Text output is followed by one :func:`gateway_runtime_lines` line per running
    gateway interpreter (macOS only). ``--json`` stays a pure list of target
    objects — and skips the probes entirely, so machine consumers keep the old
    shape and the old cost.
    """
    statuses = collect_status(home=home, root=root, platform=platform, workspace=workspace, on_path=on_path)
    if as_json:
        print(render_json(statuses))
        return 0
    print(render_text(statuses, color=_term.should_color(sys.stdout)))
    for line in gateway_runtime_lines(home=home, platform=platform):
        print(line)
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
def _dispatch(
    verb: str,
    target: str,
    *,
    force_runtime_unverified: bool = False,
    platform: str | None = None,
) -> int:
    platform = sys.platform if platform is None else platform
    if verb == "enable" and target in _ALL_CORE_TARGETS:
        eligible, reason = production_file_vault_eligibility(platform)
        if not eligible:
            _term.emit_error(f"encryption enable {target}: {reason}.")
            return 1

    from . import config_decrypt_cli, env_decrypt_cli, memory_cli

    home = _hermes_home()
    root = resolve_root(None)

    # target -> {verb: action}. enable/disable are explicit; the CLI adapters
    # only ever pass enable/disable/purge, and any non-enable/disable verb
    # resolves to the target's purge (preserves the original if-chain's
    # fall-through). workspace stays lazily imported (macOS-only path).
    # ``force_runtime_unverified`` reaches the env, config, and memory enables
    # (the runtime-gated seals); every other route ignores it.
    routes: dict[str, dict[str, Callable[[], int]]] = {
        "env": {
            "enable": lambda: env_decrypt_cli.enable(
                home=home, root=root, platform=platform, force_runtime_unverified=force_runtime_unverified
            ),
            "disable": lambda: env_decrypt_cli.disable(home=home, root=root),
            "purge": lambda: env_decrypt_cli.purge(home=home, root=root),
        },
        "config": {
            "enable": lambda: config_decrypt_cli.enable(
                home=home, root=root, platform=platform, force_runtime_unverified=force_runtime_unverified
            ),
            "disable": lambda: config_decrypt_cli.disable(home=home, root=root),
            "purge": lambda: config_decrypt_cli.purge(home=home, root=root),
        },
        "memory": {
            "enable": lambda: memory_cli.enable(
                home=home, root=root, platform=platform, force_runtime_unverified=force_runtime_unverified
            ),
            "disable": lambda: memory_cli.disable(home=home, root=root),
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


def _run_target(
    verb: str,
    target: str,
    *,
    force_runtime_unverified: bool = False,
    platform: str | None = None,
) -> tuple[str, int]:
    """Dispatch one target for an ``all`` fan-out; return ``(status_label, exit_code)``.

    The engine streams its own detail to stdout here; the caller emits the
    one-line per-target status afterwards as a single contiguous summary block.
    """
    rc = _dispatch(
        verb,
        target,
        force_runtime_unverified=force_runtime_unverified,
        platform=platform,
    )
    return ("ok" if rc == 0 else f"FAILED (exit {rc})"), rc


def _run_core_target(verb: str, target: str, *, platform: str, force_runtime_unverified: bool) -> tuple[str, int, bool]:
    """Run one core (env/config/memory) target; return ``(status_label, exit_code, skipped)``.

    Every ``enable`` is platform-gated first: production file-vault enrollment
    has a macOS device-anchor store, but no supported Linux counterpart.  A
    Linux ``enable all`` therefore reports all three core targets as clean
    skips instead of entering a ceremony that will fail in the anchor store.
    Only once the platform passes is the ``memory`` target's Hermes seam
    (:func:`memory_runtime_available`) checked; when that is also missing the
    engine would again just refuse, so it is never called — both cases record
    a skip instead of a failure. ``disable`` / ``purge`` still run regardless
    of platform or seam: they clear state and decrypt files back, which is
    exactly what a broken seam or the wrong OS needs.
    """
    if verb == "enable":
        eligible, reason = production_file_vault_eligibility(platform)
        if not eligible:
            return f"skipped ({reason})", 0, True
    if target == "memory" and verb == "enable":
        available, reason = memory_runtime_available()
        if not available:
            return f"skipped ({reason})", 0, True
    status, rc = _run_target(
        verb,
        target,
        force_runtime_unverified=force_runtime_unverified,
        platform=platform,
    )
    return status, rc, False


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
    force_runtime_unverified: bool = False,
) -> int:
    """Fan ``verb`` out over every target, best-effort. Returns an exit code.

    Core vault targets (env / config / memory) are attempted when their
    production platform is eligible; workspace is separately gated (see
    :func:`_workspace_eligible`) and a skip never counts as a failure. Under
    ``enable``, all file-vault targets are skipped off macOS, and ``memory`` is
    also skipped when this Hermes has no seam Mordred can wrap (see
    :func:`_run_core_target`). The resolved ``platform`` is passed through to
    each target, so eligibility and engine behaviour cannot disagree. Every
    eligible target runs even if an earlier one
    failed; the exit code is non-zero iff at least one *attempted* target
    failed. Per-target engine output streams inline; the ok/FAILED/skipped
    roll-up prints once at the end as a single block (see
    :func:`_print_all_summary`).

    ``force_runtime_unverified`` is forwarded to every target's dispatch but only
    affects env, config, and memory enables (the runtime-gated seals); see
    :func:`_dispatch`.
    """
    platform = sys.platform if platform is None else platform
    on_path = _default_on_path() if on_path is None else on_path

    outcomes: list[tuple[str, str]] = []
    failed = 0
    skipped = 0
    for target in _ALL_CORE_TARGETS:
        status, rc, was_skipped = _run_core_target(
            verb, target, platform=platform, force_runtime_unverified=force_runtime_unverified
        )
        outcomes.append((target, status))
        if was_skipped:
            skipped += 1
        else:
            failed += rc != 0

    eligible, reason = _workspace_eligible(verb, platform=platform, on_path=on_path)
    if eligible:
        status, rc = _run_target(
            verb,
            "workspace",
            force_runtime_unverified=force_runtime_unverified,
            platform=platform,
        )
        outcomes.append(("workspace", status))
        failed += rc != 0
    else:
        outcomes.append(("workspace", f"skipped ({reason})"))
        skipped += 1

    _print_all_summary(verb, outcomes, failed=failed, skipped=skipped)
    platform_eligible, _reason = production_file_vault_eligibility(platform)
    if verb == "enable" and not platform_eligible:
        _term.emit_warn(file_vault_plaintext_warning(platform))
    return 1 if failed else 0


def cli_enable(args: argparse.Namespace) -> int:
    force = bool(getattr(args, "force_runtime_unverified", False))
    if args.target == "all":
        return _dispatch_all("enable", force_runtime_unverified=force)
    return _dispatch("enable", args.target, force_runtime_unverified=force)


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
        workspace_targets = ""
        if args.target in {"workspace", "all"}:
            workspace = resolve_workspace_env()
            workspace_targets = f" Workspace targets: volume={workspace.image}; key material={workspace.keydir}."
        _term.emit_error(
            f"encryption purge {args.target} is destructive (removes {scope}).{workspace_targets} "
            "Re-run with --yes to confirm."
        )
        return 2
    if args.target == "all":
        return _dispatch_all("purge")
    return _dispatch("purge", args.target)
