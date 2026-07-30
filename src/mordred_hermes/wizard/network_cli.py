"""Handlers for ``hermes mordred network {use,status,init}``.

Responsibilities:

1. **Persist the user's desired default path** to
   ``~/.hermes/config.yaml plugins.mordred_network.default_path`` so
   the next ``hermes`` session brings that path up automatically at
   ``on_session_start`` (see :mod:`mordred_hermes.network.hooks`).
2. **Switch the in-process runtime live** when one is registered. From
   a standalone ``hermes-mordred`` invocation no runtime is registered
   (different process from the long-running ``hermes`` agent), so the
   handler degrades gracefully: write to disk, tell the user the
   change is deferred to the next session.
3. **``network init``** — on-demand setup of the network-privacy path,
   Tor binary/port, and Mullvad account/relay/killswitch. Moved out of
   ``configure`` so first-run setup stays short; re-runnable (seeds prompt
   defaults from disk; a blank Mullvad answer keeps the current secret).

The :class:`NetworkAnswers` data model and the input coercions live in
:mod:`mordred_hermes.wizard._network_answers`; the interactive answer
collection lives in :mod:`mordred_hermes.wizard._network_init`. Both are
re-exported here so existing ``from .network_cli import NetworkAnswers`` /
``collect_network_answers`` callers keep working unchanged.

The CLI itself does not write audit entries - it is a thin user-facing
wrapper around :mod:`mordred_hermes.network.api` and the wizard writers.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from .._home import HERMES_BASE
from .._yaml_io import load_plugin_section
from ..network import api
from ..network._exceptions import MordredNetworkError
from ..network.guidance import dependency_warning
from ..network.settings import read_default_path
from . import _term
from ._network_answers import (
    _VALID_PATHS,
    NetworkAnswers,
    NetworkInitInputs,
)
from ._network_init import (
    collect_network_answers,
    network_answers_from_args,
)
from .configure import (
    PromptIO,
    PromptToolkitIO,
)
from .credentials_writer import CredentialsWriter, JSONCredentialsWriter
from .env_file_writer import DotEnvFileWriter, EnvFileWriter
from .policy_writer import PolicyWriter

_LOG = logging.getLogger("mordred.wizard.network_cli")

DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"


# --------------------------------------------------------------------------- #
# Public handlers                                                             #
# --------------------------------------------------------------------------- #


def handle_use(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network use <path>``.

    Always writes the choice to ``config.yaml``. If a runtime is registered,
    :func:`api.use` verifies that the frozen process route already matches.
    A conflicting route stays persisted for the next Hermes process and the
    live request returns non-zero with restart guidance.
    """
    target = str(getattr(args, "path", ""))
    if target not in _VALID_PATHS:
        _term.emit_error(f"unknown network path {target!r}; choose one of {_VALID_PATHS}")
        return 2

    config_path = _resolve_config_path(args)

    try:
        _write_default_path_to_config(config_path, target)
    except OSError as e:
        _term.emit_error(f"failed to write {config_path}: {e}")
        return 1

    live = _runtime_registered()
    if not live:
        print(f"Route set to `{target}` (saved to {config_path}).")
        print("It takes effect on the next `hermes` session; the process running now keeps its current route.")
        warning = _dependency_warning_for_configured_path(config_path, target)
        if warning:
            # Stays on stdout (it follows the route-set success lines), but reads
            # as a warning: styled yellow on a tty, byte-identical off it.
            print(_term.warn(warning, enabled=_term.should_color(sys.stdout)))
        return 0

    try:
        api.use(target)  # type: ignore[arg-type]
    except MordredNetworkError as e:
        _term.emit_error(f"switching to {target} failed: {e}")
        return 1
    print(f"Route `{target}` is already active (also saved to {config_path}).")
    return 0


def handle_status(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network status``.

    Shows live runtime state when available, else the disk-configured
    default with a "(not active in this process)" marker so the user
    can tell whether the value they see is currently routing traffic.
    """
    config_path = _resolve_config_path(args)
    as_json = bool(getattr(args, "json", False))
    if _runtime_registered():
        s = api.status()
        if as_json:
            body = {
                "live": True,
                "active_path": s.active_path,
                "ready": s.ready,
                "last_health": s.last_health,
                "dropped": api.is_dropped(),
            }
            print(json.dumps(body, indent=2))
            return 0
        ready_label = "ready" if s.ready else "not ready"
        last_health = "ok" if s.last_health else "FAILED"
        print(f"active_path = {s.active_path}  state = {ready_label}  last_health = {last_health}")
        if api.is_dropped():
            print(
                "  [warning] path was flagged as DROPPED by the liveness worker. "
                "Strict-mode tool and provider calls will refuse. Restart Hermes "
                "so the process route and provider clients are rebuilt together."
            )
        return 0

    configured = _read_default_path_from_config(config_path)
    if as_json:
        print(json.dumps({"live": False, "configured_path": configured}, indent=2))
        return 0
    print(f"configured default_path = {configured}  (runtime not active in this process)")
    return 0


# --------------------------------------------------------------------------- #
# Internals                                                                   #
# --------------------------------------------------------------------------- #


def _resolve_config_path(args: argparse.Namespace) -> Path:
    """Honour an injected ``config_path`` (tests) but fall back to default."""
    override = getattr(args, "config_path", None)
    if isinstance(override, Path):
        return override
    return DEFAULT_CONFIG_PATH


def _runtime_registered() -> bool:
    """Has the plugin's ``register(ctx)`` already run in this process?"""
    try:
        api.status()
    except MordredNetworkError:
        return False
    return True


def _write_default_path_to_config(config_path: Path, default_path: str) -> None:
    """Merge ``default_path`` into ``plugins.mordred_network`` via PolicyWriter.

    Routes through :meth:`PolicyWriter.merge_mordred_sections` so a
    ``network use clearnet`` invocation does NOT clobber ``tor_binary_path`` /
    ``tor_socks_port`` / ``mullvad_*`` written earlier by
    ``hermes-mordred network init`` or by hand.

    The merge path inherits the canonical ``_atomic_write_text`` (tempfile +
    ``os.replace``) guarantee from the writer pipeline, so a crash or
    concurrent ``hermes mordred configure`` invocation cannot truncate the
    file -- readers always see either the pre-write or post-write content.
    """
    from .policy_writer import PolicyWriter

    PolicyWriter(config_path=config_path).merge_mordred_sections({"mordred_network": {"default_path": default_path}})


def _read_default_path_from_config(config_path: Path) -> str:
    """Read ``plugins.mordred_network.default_path`` or fall back to clearnet.

    Validation delegates to ``network.settings.read_default_path`` so the
    wizard reports exactly the path the runtime would bootstrap with.
    """
    return read_default_path(config_path, log=_LOG)


def _dependency_warning_for_configured_path(config_path: Path, target: str) -> str | None:
    """Warn when the selected path needs a missing external program."""
    network = _read_existing_network_section(config_path)
    raw_tor_binary = network.get("tor_binary_path")
    tor_binary = raw_tor_binary if isinstance(raw_tor_binary, str) and raw_tor_binary else "tor"
    raw_provider = network.get("vpn_provider")
    vpn_provider = raw_provider if isinstance(raw_provider, str) and raw_provider else "mullvad"
    raw_up = network.get("custom_up_cmd")
    custom_up_cmd = tuple(raw_up) if isinstance(raw_up, list) and all(isinstance(x, str) for x in raw_up) else ()
    raw_wg = network.get("wireguard_config_path")
    wireguard_config_path = raw_wg if isinstance(raw_wg, str) else ""
    return dependency_warning(
        target,
        tor_binary=tor_binary,
        vpn_provider=vpn_provider,
        custom_up_cmd=custom_up_cmd,
        wireguard_config_path=wireguard_config_path,
    )


# --------------------------------------------------------------------------- #
# network init -- on-demand network privacy setup (formerly in `configure`)   #
# --------------------------------------------------------------------------- #


def run_init(
    *,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    env_writer: EnvFileWriter,
    credentials_writer: CredentialsWriter,
    env_path: Path | None = None,
    credentials_path: Path | None = None,
    clear_mullvad: bool = False,
) -> int:
    """Collect answers interactively, then persist. Returns an exit code.

    ``clear_mullvad`` removes the stored Mullvad secret (and skips the secret
    prompt). See :func:`_persist_network` for the persistence contract.
    """
    existing = _read_existing_network_section(policy_writer.config_path)
    inputs = collect_network_answers(prompt_io, existing=existing, prompt_secret=not clear_mullvad)
    return _persist_network(
        inputs,
        policy_writer=policy_writer,
        env_writer=env_writer,
        credentials_writer=credentials_writer,
        env_path=env_path,
        credentials_path=credentials_path,
        clear_mullvad=clear_mullvad,
    )


def _persist_network(
    inputs: NetworkInitInputs,
    *,
    policy_writer: PolicyWriter,
    env_writer: EnvFileWriter,
    credentials_writer: CredentialsWriter,
    env_path: Path | None = None,
    credentials_path: Path | None = None,
    clear_mullvad: bool = False,
) -> int:
    """Persist collected network-privacy answers. Returns an exit code.

    - ``plugins.mordred_network`` is **merged** (not whole-replaced) into
      ``config.yaml`` so unrelated user-edited sub-fields survive.
    - Mullvad secret: ``clear_mullvad`` removes the ``~/.hermes/.env`` line;
      otherwise a non-empty secret is written and a blank one is a no-op
      (keeping the current secret across re-runs).
    - The relay/killswitch indirection goes to the :class:`CredentialsWriter`
      (``~/.hermes/mordred/credentials/network.json``).

    All three writes are guarded by the same ``except OSError`` convention
    :func:`handle_use` already applies to its single PolicyWriter write: a
    disk-write failure (full disk, permission error, read-only ``~/.hermes``)
    reports a clean ``error:`` line + exit 1 instead of an unhandled traceback
    from ``network init``.
    """
    na = inputs.network_answers
    resolved_env_path = env_path if env_path is not None else (HERMES_BASE / ".env")
    resolved_credentials_path = (
        credentials_path if credentials_path is not None else (HERMES_BASE / "mordred" / "credentials" / "network.json")
    )
    # ``secret_written`` / ``secret_cleared`` are bools (never the plaintext); the
    # secret itself is accessed only inline at the upsert call, so it never sits
    # in this frame's locals where --showlocals / a debugger / a rich traceback
    # could surface it (Codex review 2026-06-05).
    secret_written = False
    secret_cleared = False
    try:
        policy_writer.merge_mordred_sections({"mordred_network": na.to_config_yaml_section()})

        if clear_mullvad:
            env_writer.upsert(resolved_env_path, key=na.mullvad_account_id_env, value="")
            secret_cleared = True
        elif inputs._mullvad_account_secret:
            env_writer.upsert(
                resolved_env_path,
                key=na.mullvad_account_id_env,
                value=inputs._mullvad_account_secret,
            )
            secret_written = True
        # else: blank => leave the existing .env untouched (keep the current secret).

        credentials_writer.write_network(
            resolved_credentials_path,
            mullvad_account_id_env=na.mullvad_account_id_env,
            mullvad_relay_country=na.mullvad_relay_country,
            mullvad_killswitch=na.mullvad_killswitch,
        )
    except OSError as e:
        _term.emit_error(f"failed to persist network settings: {e}")
        return 1

    print(_init_summary(na, secret_written=secret_written, secret_cleared=secret_cleared))
    return 0


def handle_init(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network init``.

    ``--non-interactive`` is flag-driven (no prompts, no abort): the answers
    come from the CLI flags, seeded from the existing config, and the Mullvad
    secret is left unchanged unless ``--clear-mullvad`` removes it. Otherwise
    the prompts run interactively. The production writers are used in both modes.
    """
    non_interactive = bool(getattr(args, "non_interactive", False))
    clear_mullvad = bool(getattr(args, "clear_mullvad", False))
    config_path = _resolve_config_path(args)
    policy_writer = PolicyWriter(config_path=config_path)
    env_writer = DotEnvFileWriter()
    credentials_writer = JSONCredentialsWriter()

    if non_interactive:
        existing = _read_existing_network_section(config_path)
        inputs = network_answers_from_args(args, existing=existing)
        return _persist_network(
            inputs,
            policy_writer=policy_writer,
            env_writer=env_writer,
            credentials_writer=credentials_writer,
            clear_mullvad=clear_mullvad,
        )

    return run_init(
        prompt_io=PromptToolkitIO(),
        policy_writer=policy_writer,
        env_writer=env_writer,
        credentials_writer=credentials_writer,
        clear_mullvad=clear_mullvad,
    )


def _read_existing_network_section(config_path: Path) -> dict[str, Any]:
    """Return the current ``plugins.mordred_network`` body, or ``{}``.

    Used to seed :func:`collect_network_answers` defaults so a re-run keeps
    existing values. Any read/parse error collapses to ``{}`` (the prompts
    then fall back to their safe static defaults).
    """
    return load_plugin_section(config_path, "mordred_network", log=_LOG) or {}


def _join_cmd_or(cmd: tuple[str, ...], empty: str) -> str:
    """Render an argv tuple as a space-joined line, or a placeholder when empty."""
    return " ".join(cmd) if cmd else empty


def _provider_summary_lines(na: NetworkAnswers, *, killswitch: str, account: str) -> list[str]:
    """Provider-specific lines for the init summary.

    Only the selected provider's settings are echoed: a custom/wireguard provider
    shows its own command/config and drops the Mullvad relay/account lines that do
    not apply to it.
    """
    if na.vpn_provider == "custom":
        return [
            "  vpn provider       : custom",
            f"  vpn up command     : {_join_cmd_or(na.custom_up_cmd, '(unset)')}",
            f"  vpn down command   : {_join_cmd_or(na.custom_down_cmd, '(unset)')}",
            f"  vpn health command : {_join_cmd_or(na.custom_health_cmd, '(none)')}",
        ]
    if na.vpn_provider == "wireguard":
        return [
            "  vpn provider       : wireguard",
            f"  wireguard config   : {na.wireguard_config_path or '(unset)'}",
        ]
    return [
        f"  mullvad relay      : {na.mullvad_relay_country}",
        f"  mullvad killswitch : {killswitch}",
        f"  mullvad account    : {account}",
    ]


def _init_summary(na: NetworkAnswers, *, secret_written: bool, secret_cleared: bool = False) -> str:
    """User-facing confirmation printed after a successful ``network init``.

    Echoes the resolved settings so the user can verify what was saved, and
    whether the Mullvad secret was stored, cleared, or left unchanged.
    """
    killswitch = "enabled" if na.mullvad_killswitch else "disabled"
    if secret_cleared:
        account = "cleared"
    elif secret_written:
        account = "stored in ~/.hermes/.env"
    else:
        account = "unchanged"
    lines = [
        "",
        "Network privacy initialised:",
        f"  default path       : {na.default_network_path}",
        f"  tor binary         : {na.tor_binary_path}",
        f"  tor socks port     : {na.tor_socks_port}",
        *_provider_summary_lines(na, killswitch=killswitch, account=account),
    ]
    if na.default_network_path == "clearnet":
        lines.append("  note: clearnet = no anonymising layer; re-run and pick tor/vpn to enable privacy.")
    warning = dependency_warning(
        na.default_network_path,
        tor_binary=na.tor_binary_path,
        vpn_provider=na.vpn_provider,
        custom_up_cmd=na.custom_up_cmd,
        wireguard_config_path=na.wireguard_config_path,
    )
    if warning:
        lines.append(f"  {warning}")
    lines.append("  Applied when Hermes next starts; restart a running Hermes process to rebuild its route.")
    return "\n".join(lines)


__all__ = [
    "NetworkAnswers",
    "NetworkInitInputs",
    "collect_network_answers",
    "handle_init",
    "handle_status",
    "handle_use",
    "network_answers_from_args",
    "run_init",
]
