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

The CLI itself does not write audit entries - it is a thin user-facing
wrapper around :mod:`mordred_hermes.network.api` and the wizard writers.
"""

from __future__ import annotations

import argparse
import json
import logging
import shlex
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from .._home import HERMES_BASE
from ..network import api
from ..network._exceptions import MordredNetworkError
from ..network.guidance import dependency_warning
from .configure import (
    PromptIO,
    PromptToolkitIO,
)
from .credentials_writer import CredentialsWriter, JSONCredentialsWriter
from .env_file_writer import DotEnvFileWriter, EnvFileWriter
from .policy_writer import PolicyWriter

_LOG = logging.getLogger("mordred.wizard.network_cli")

DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
_VALID_PATHS = ("tor", "vpn", "clearnet")

DEFAULT_TOR_SOCKS_PORT: Final[int] = 9050
MULLVAD_ACCOUNT_ENV_VAR_NAME: Final[str] = "MORDRED_MULLVAD_ACCOUNT"


#: Inline descriptions shown next to each route in the ``network init``
#: privacy-path radio dialog (rendered as ``<route> — <description>`` by
#: ``PromptToolkitIO``). Before this each prompt opened as a bare label with no
#: hint of what it does (UX request 2026-06-15); these orient the operator the
#: same way the keyvault-init intro and the ``configure`` policy-mode
#: descriptions do. Copy condenses the "What each route is" section of
#: ``mordred-docs/mordred/QUICKSTART.md`` so the wizard and the docs never drift.
_NETWORK_PATH_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "tor": "Anonymity via the Tor network — slowest; needs `tor` installed",
    "vpn": "IP privacy via Mullvad VPN — faster; needs a paid Mullvad account",
    "clearnet": "Direct connection — no anonymity, fastest (the default)",
}

#: Help line printed above each plain-text / secret / yes-no ``network init``
#: prompt (UX request 2026-06-15). Every setting only matters for a single
#: route, so each line names its route up front — a clearnet user can press
#: Enter straight through. Mirrors the per-prompt Tor / VPN tables in
#: ``mordred-docs/mordred/QUICKSTART.md``.
_TOR_BINARY_DESCRIPTION: Final[str] = (
    "Tor route only — where the `tor` program is. Leave as `tor` if it's on your PATH."
)
_TOR_SOCKS_PORT_DESCRIPTION: Final[str] = (
    "Tor route only — local port Tor's SOCKS proxy listens on. Standard is 9050; rarely changed."
)
_MULLVAD_ACCOUNT_DESCRIPTION: Final[str] = (
    "VPN route only — your Mullvad account number (Mullvad is a paid VPN service)."
)
_MULLVAD_RELAY_DESCRIPTION: Final[str] = (
    "VPN route only — `auto`, or a 2-letter country code (e.g. `se`) to pin the VPN exit country."
)
_MULLVAD_KILLSWITCH_DESCRIPTION: Final[str] = (
    "VPN route only — lockdown mode: block all traffic if the VPN drops, so your real IP can't leak."
)

#: Provider selector shown when the `vpn` route is in play. Mullvad is the
#: recommended default (strict-capable); wireguard / custom let you use any
#: other VPN (off / lenient only — see QUICKSTART "Using a different VPN").
_VPN_PROVIDER_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "mullvad": "Recommended. Paid Mullvad account; the only provider allowed in strict mode.",
    "wireguard": "Any VPN with a WireGuard `.conf` (Proton VPN, IVPN, self-hosted). off/lenient only.",
    "custom": "Any VPN driven by its own CLI (ExpressVPN, NordVPN). off/lenient only.",
}
_VPN_PROVIDER_DESCRIPTION: Final[str] = (
    "VPN route only — which VPN to use. `mullvad` (recommended) or `wireguard` / `custom` for any other VPN."
)
_WIREGUARD_CONFIG_DESCRIPTION: Final[str] = (
    "wireguard provider only — path to your WireGuard `.conf` (exported from Proton VPN, IVPN, etc.)."
)
_CUSTOM_UP_DESCRIPTION: Final[str] = (
    "custom provider only — command that connects the VPN, e.g. `expressvpn connect` or `nordvpn connect`."
)
_CUSTOM_DOWN_DESCRIPTION: Final[str] = (
    "custom provider only — command that disconnects the VPN, e.g. `expressvpn disconnect`."
)
_CUSTOM_HEALTH_DESCRIPTION: Final[str] = (
    "custom provider only — optional command that reports tunnel status, e.g. `expressvpn status` (blank = none)."
)


def _split_cmd(raw: str) -> tuple[str, ...]:
    """Parse a command string into an argv tuple (shell-style, no exec).

    ``shlex.split`` only tokenises (handles quotes/spaces); it never runs a
    shell, so this is purely how the operator's typed command becomes the
    argv list the custom provider executes without ``shell=True``.
    """
    try:
        return tuple(shlex.split(raw.strip()))
    except ValueError:
        # Unbalanced quotes etc. — fall back to a naive split so a typo
        # doesn't abort the whole `network init` session.
        return tuple(raw.split())


def _join_cmd(value: object) -> str:
    """Render a stored argv list back to an editable command string."""
    if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
        return shlex.join(value)
    return ""


def _seed_cmd(value: object) -> tuple[str, ...]:
    """Coerce a stored YAML argv list to a tuple (else empty)."""
    if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
        return tuple(value)
    return ()


# --------------------------------------------------------------------------- #
# Public handlers                                                             #
# --------------------------------------------------------------------------- #


def handle_use(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network use <path>``.

    Always writes the choice to ``config.yaml``. If a runtime is
    registered, also drives :func:`api.use` for live effect. Returns 0
    on success, non-zero when the live switch raised.
    """
    target = str(getattr(args, "path", ""))
    if target not in _VALID_PATHS:
        print(f"error: unknown network path {target!r}; choose one of {_VALID_PATHS}", file=sys.stderr)
        return 2

    config_path = _resolve_config_path(args)

    try:
        _write_default_path_to_config(config_path, target)
    except OSError as e:
        print(f"error: failed to write {config_path}: {e}", file=sys.stderr)
        return 1

    live = _runtime_registered()
    if not live:
        print(f"Route set to `{target}` (saved to {config_path}).")
        print("It takes effect on the next `hermes` session; the process running now keeps its current route.")
        warning = _dependency_warning_for_configured_path(config_path, target)
        if warning:
            print(warning)
        return 0

    try:
        api.use(target)  # type: ignore[arg-type]
    except MordredNetworkError as e:
        print(f"error: switching to {target} failed: {e}", file=sys.stderr)
        return 1
    print(f"Route switched to `{target}` now (also saved to {config_path}).")
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
                "  [warning] path was flagged as DROPPED by the liveness "
                "worker. Strict-mode tool calls will refuse until the path "
                "is re-bring-up'd via `hermes-mordred network use <path>`."
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
    """Read ``plugins.mordred_network.default_path`` or fall back to clearnet."""
    if not config_path.exists():
        return "clearnet"
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    yaml = YAML(typ="safe", pure=True)
    try:
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except (OSError, YAMLError) as e:
        _LOG.warning("could not read %s: %s", config_path, e)
        return "clearnet"
    if not isinstance(data, dict):
        return "clearnet"
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return "clearnet"
    network = plugins.get("mordred_network")
    if not isinstance(network, dict):
        return "clearnet"
    value = network.get("default_path", "clearnet")
    if isinstance(value, str) and value in _VALID_PATHS:
        return value
    return "clearnet"


def _dependency_warning_for_configured_path(config_path: Path, target: str) -> str | None:
    """Warn when the selected path needs a missing external program."""
    network = _read_existing_network_section(config_path)
    raw_tor_binary = network.get("tor_binary_path")
    tor_binary = raw_tor_binary if isinstance(raw_tor_binary, str) and raw_tor_binary else "tor"
    return dependency_warning(target, tor_binary=tor_binary)


# --------------------------------------------------------------------------- #
# network init -- on-demand network privacy setup (formerly in `configure`)   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class NetworkAnswers:
    """The six wizard outputs that drive network path management.

    The Mullvad account *value* never appears here -- only the env-var
    REFERENCE. The actual secret flows through the :class:`EnvFileWriter`
    which writes it to ``~/.hermes/.env`` at mode 0600.

    :meth:`to_config_yaml_section` returns the body merged into
    ``plugins.mordred_network`` in ``config.yaml``.
    """

    default_network_path: str  # "tor" | "vpn" | "clearnet"
    tor_binary_path: str  # filesystem path or shell-resolvable name
    tor_socks_port: int
    mullvad_account_id_env: str  # always ``MORDRED_MULLVAD_ACCOUNT``
    mullvad_relay_country: str  # "auto" | 2-letter code
    mullvad_killswitch: bool
    # Pluggable VPN provider behind the `vpn` route. Defaults keep older
    # callers / configs on Mullvad unchanged.
    vpn_provider: str = "mullvad"  # "mullvad" | "wireguard" | "custom"
    wireguard_config_path: str = ""  # vpn_provider="wireguard"
    custom_up_cmd: tuple[str, ...] = ()  # vpn_provider="custom"
    custom_down_cmd: tuple[str, ...] = ()
    custom_health_cmd: tuple[str, ...] = ()

    def to_config_yaml_section(self) -> dict[str, object]:
        """The body merged into ``plugins.mordred_network`` in config.yaml.

        Key remap: ``default_network_path`` becomes ``default_path`` on disk so
        the network reader (``mordred_hermes.network`` /
        :func:`_read_default_path_from_config`) keeps working unchanged.

        Provider-specific keys are emitted only when set, so a Mullvad config
        stays free of empty wireguard/custom entries.
        """
        section: dict[str, object] = {
            "default_path": self.default_network_path,
            "tor_binary_path": self.tor_binary_path,
            "tor_socks_port": self.tor_socks_port,
            "mullvad_account_id_env": self.mullvad_account_id_env,
            "mullvad_relay_country": self.mullvad_relay_country,
            "mullvad_killswitch": self.mullvad_killswitch,
            "vpn_provider": self.vpn_provider,
        }
        if self.wireguard_config_path:
            section["wireguard_config_path"] = self.wireguard_config_path
        if self.custom_up_cmd:
            section["custom_up_cmd"] = list(self.custom_up_cmd)
        if self.custom_down_cmd:
            section["custom_down_cmd"] = list(self.custom_down_cmd)
        if self.custom_health_cmd:
            section["custom_health_cmd"] = list(self.custom_health_cmd)
        return section


def _coerce_tor_socks_port(raw: str) -> int:
    """Parse a port string; fall back to the default 9050 on garbage input.

    Hard-aborting on bad input would force the user to abandon a whole
    ``network init`` session for a typo. A WARN log + safe-default lets them
    re-run and fix it.
    """
    try:
        port = int(raw)
    except ValueError:
        _LOG.warning("Invalid Tor SOCKS port %r; falling back to default %d", raw, DEFAULT_TOR_SOCKS_PORT)
        return DEFAULT_TOR_SOCKS_PORT
    if port <= 0 or port > 65535:
        _LOG.warning("Tor SOCKS port %d out of range; falling back to default %d", port, DEFAULT_TOR_SOCKS_PORT)
        return DEFAULT_TOR_SOCKS_PORT
    return port


def _coerce_mullvad_relay_country(raw: str) -> str:
    """Normalize the Mullvad relay-country answer to ``"auto"`` or a 2-letter
    lowercase ISO code.

    The Mullvad CLI accepts ``relay set location <code>`` only for 2-letter
    codes (or the sentinel ``"any"`` / ``"auto"``). Free-text typos like
    ``"unitedstates"`` would silently flow into config and only surface at
    bring-up time. Like :func:`_coerce_tor_socks_port`, garbage falls back to
    the safe default (``"auto"``) with a WARN rather than aborting.
    """
    stripped = raw.strip()
    if not stripped or stripped.lower() == "auto":
        return "auto"
    if len(stripped) == 2 and stripped.isalpha():
        return stripped.lower()
    _LOG.warning(
        "Invalid Mullvad relay country %r; expected 'auto' or 2-letter ISO code; falling back to 'auto'",
        raw,
    )
    return "auto"


def _coerce_seed_bool(value: object) -> bool:
    """Interpret a yes/no prompt seed default robustly.

    config.yaml written by Mordred stores a real YAML bool, but a hand-edited
    quoted value like ``"false"`` would otherwise pass ``bool("false") is True``
    and flip the killswitch default on a re-run. Treat the common string forms
    explicitly (Codex review 2026-06-05).
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


@dataclass(frozen=True, slots=True)
class NetworkInitInputs:
    """Transient carrier from :func:`collect_network_answers` to :func:`run_init`.

    Holds the env-var-only :class:`NetworkAnswers` plus the raw Mullvad secret
    on a ``repr=False`` field. Mirrors the redaction contract that
    ``configure.ConfigureResult`` used: ``repr``/``str`` (called implicitly by
    tracebacks, ``pytest --showlocals``, loggers, debuggers) must never emit
    the plaintext account number. The secret is routed to the
    :class:`EnvFileWriter` by ``run_init`` and otherwise discarded.
    """

    network_answers: NetworkAnswers
    _mullvad_account_secret: str = field(default="", repr=False)


def _collect_vpn_provider(
    prompt_io: PromptIO, *, existing: Mapping[str, Any]
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Ask which VPN provider to use plus its provider-specific settings.

    Asked after the Mullvad prompts so the Mullvad-only prompt order the
    older wizard tests rely on is unchanged; the wireguard / custom prompts
    appear only when that provider is selected. Returns
    ``(vpn_provider, wireguard_config_path, up, down, health)``.
    """
    vpn_provider = prompt_io.ask_choice(
        label="VPN provider",
        choices=("mullvad", "wireguard", "custom"),
        default=str(existing.get("vpn_provider") or "mullvad"),
        descriptions=_VPN_PROVIDER_DESCRIPTIONS,
    )
    wireguard_config_path = ""
    custom_up: tuple[str, ...] = ()
    custom_down: tuple[str, ...] = ()
    custom_health: tuple[str, ...] = ()
    if vpn_provider == "wireguard":
        wireguard_config_path = prompt_io.ask_text(
            label="WireGuard config path",
            default=str(existing.get("wireguard_config_path") or ""),
            description=_WIREGUARD_CONFIG_DESCRIPTION,
        ).strip()
    elif vpn_provider == "custom":
        custom_up = _split_cmd(
            prompt_io.ask_text(
                label="VPN up command",
                default=_join_cmd(existing.get("custom_up_cmd")),
                description=_CUSTOM_UP_DESCRIPTION,
            )
        )
        custom_down = _split_cmd(
            prompt_io.ask_text(
                label="VPN down command",
                default=_join_cmd(existing.get("custom_down_cmd")),
                description=_CUSTOM_DOWN_DESCRIPTION,
            )
        )
        custom_health = _split_cmd(
            prompt_io.ask_text(
                label="VPN health command",
                default=_join_cmd(existing.get("custom_health_cmd")),
                description=_CUSTOM_HEALTH_DESCRIPTION,
            )
        )
    return vpn_provider, wireguard_config_path, custom_up, custom_down, custom_health


def collect_network_answers(
    prompt_io: PromptIO,
    *,
    existing: Mapping[str, Any] | None = None,
    prompt_secret: bool = True,
) -> NetworkInitInputs:
    """Run the six network-privacy prompts, seeding defaults from ``existing``.

    ``existing`` is the current ``plugins.mordred_network`` body (see
    :func:`_read_existing_network_section`). Seeding each prompt's default from
    it makes a re-run of ``network init`` non-destructive: pressing Enter on
    every prompt keeps the on-disk value. A blank Mullvad answer is preserved
    as ``""`` so :func:`run_init` can leave any existing ``.env`` secret intact
    instead of stripping it.
    """
    existing = existing or {}

    seeded_path = existing.get("default_path")
    if not (isinstance(seeded_path, str) and seeded_path in _VALID_PATHS):
        seeded_path = "clearnet"

    default_network_path = prompt_io.ask_choice(
        label="Network privacy path",
        choices=_VALID_PATHS,
        default=seeded_path,
        descriptions=_NETWORK_PATH_DESCRIPTIONS,
    )
    tor_binary_path = prompt_io.ask_text(
        label="Tor binary path",
        default=str(existing.get("tor_binary_path") or "tor"),
        description=_TOR_BINARY_DESCRIPTION,
    )
    tor_socks_port = _coerce_tor_socks_port(
        prompt_io.ask_text(
            label="Tor SOCKS port",
            default=str(existing.get("tor_socks_port") or DEFAULT_TOR_SOCKS_PORT),
            description=_TOR_SOCKS_PORT_DESCRIPTION,
        )
    )
    # Blank = keep the current secret (re-run safe). The label says so. When the
    # caller has already decided to clear the secret (``--clear-mullvad``), skip
    # the prompt entirely.
    if prompt_secret:
        mullvad_account_secret = prompt_io.ask_password(
            label="Mullvad account number (blank = keep current; stored in ~/.hermes/.env)",
            default="",
            description=_MULLVAD_ACCOUNT_DESCRIPTION,
        )
    else:
        mullvad_account_secret = ""
    mullvad_relay_country = _coerce_mullvad_relay_country(
        prompt_io.ask_text(
            label="Mullvad relay country (`auto` or 2-letter code)",
            default=str(existing.get("mullvad_relay_country") or "auto"),
            description=_MULLVAD_RELAY_DESCRIPTION,
        )
    )
    mullvad_killswitch = prompt_io.ask_bool(
        label="Mullvad killswitch (lockdown-mode)",
        default=_coerce_seed_bool(existing.get("mullvad_killswitch", False)),
        description=_MULLVAD_KILLSWITCH_DESCRIPTION,
    )
    vpn_provider, wireguard_config_path, custom_up, custom_down, custom_health = _collect_vpn_provider(
        prompt_io, existing=existing
    )

    network_answers = NetworkAnswers(
        default_network_path=default_network_path,
        tor_binary_path=tor_binary_path,
        tor_socks_port=tor_socks_port,
        mullvad_account_id_env=MULLVAD_ACCOUNT_ENV_VAR_NAME,
        mullvad_relay_country=mullvad_relay_country,
        mullvad_killswitch=mullvad_killswitch,
        vpn_provider=vpn_provider,
        wireguard_config_path=wireguard_config_path,
        custom_up_cmd=custom_up,
        custom_down_cmd=custom_down,
        custom_health_cmd=custom_health,
    )
    return NetworkInitInputs(
        network_answers=network_answers,
        _mullvad_account_secret=mullvad_account_secret,
    )


def network_answers_from_args(
    args: argparse.Namespace,
    *,
    existing: Mapping[str, Any] | None = None,
) -> NetworkInitInputs:
    """Build :class:`NetworkInitInputs` from non-interactive CLI flags.

    Unspecified flags fall back to the existing on-disk section, then to the
    safe static defaults. The Mullvad secret is never taken from a flag (it
    would leak via ``ps`` / shell history): non-interactive runs keep the
    existing secret (or clear it via ``--clear-mullvad``), so the carrier
    secret is always ``""``.
    """
    existing = existing or {}

    path = getattr(args, "path", None) or existing.get("default_path") or "clearnet"
    if not (isinstance(path, str) and path in _VALID_PATHS):
        path = "clearnet"

    tor_binary_path = getattr(args, "tor_binary", None) or str(existing.get("tor_binary_path") or "tor")

    port_arg = getattr(args, "tor_socks_port", None)
    port_seed = port_arg if port_arg is not None else (existing.get("tor_socks_port") or DEFAULT_TOR_SOCKS_PORT)
    tor_socks_port = _coerce_tor_socks_port(str(port_seed))

    relay_arg = getattr(args, "mullvad_relay", None)
    relay_seed = relay_arg if relay_arg is not None else (existing.get("mullvad_relay_country") or "auto")
    mullvad_relay_country = _coerce_mullvad_relay_country(str(relay_seed))

    killswitch_arg = getattr(args, "mullvad_killswitch", None)
    mullvad_killswitch = (
        killswitch_arg
        if isinstance(killswitch_arg, bool)
        else _coerce_seed_bool(existing.get("mullvad_killswitch", False))
    )

    # The provider selection has no CLI flags yet; a non-interactive re-run
    # preserves whatever the interactive wizard / config.yaml already set.
    vpn_provider = str(existing.get("vpn_provider") or "mullvad")
    wireguard_config_path = str(existing.get("wireguard_config_path") or "")

    network_answers = NetworkAnswers(
        default_network_path=path,
        tor_binary_path=tor_binary_path,
        tor_socks_port=tor_socks_port,
        mullvad_account_id_env=MULLVAD_ACCOUNT_ENV_VAR_NAME,
        mullvad_relay_country=mullvad_relay_country,
        mullvad_killswitch=mullvad_killswitch,
        vpn_provider=vpn_provider,
        wireguard_config_path=wireguard_config_path,
        custom_up_cmd=_seed_cmd(existing.get("custom_up_cmd")),
        custom_down_cmd=_seed_cmd(existing.get("custom_down_cmd")),
        custom_health_cmd=_seed_cmd(existing.get("custom_health_cmd")),
    )
    return NetworkInitInputs(network_answers=network_answers, _mullvad_account_secret="")


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
    """
    na = inputs.network_answers
    policy_writer.merge_mordred_sections({"mordred_network": na.to_config_yaml_section()})

    resolved_env_path = env_path if env_path is not None else (HERMES_BASE / ".env")
    # ``secret_written`` / ``secret_cleared`` are bools (never the plaintext); the
    # secret itself is accessed only inline at the upsert call, so it never sits
    # in this frame's locals where --showlocals / a debugger / a rich traceback
    # could surface it (Codex review 2026-06-05).
    secret_written = False
    secret_cleared = False
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

    resolved_credentials_path = (
        credentials_path if credentials_path is not None else (HERMES_BASE / "mordred" / "credentials" / "network.json")
    )
    credentials_writer.write_network(
        resolved_credentials_path,
        mullvad_account_id_env=na.mullvad_account_id_env,
        mullvad_relay_country=na.mullvad_relay_country,
        mullvad_killswitch=na.mullvad_killswitch,
    )

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
    if not config_path.exists():
        return {}
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    yaml = YAML(typ="safe", pure=True)
    try:
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except (OSError, YAMLError) as e:
        _LOG.warning("could not read %s: %s", config_path, e)
        return {}
    if not isinstance(data, dict):
        return {}
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return {}
    section = plugins.get("mordred_network")
    if not isinstance(section, dict):
        return {}
    return dict(section)


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
        f"  mullvad relay      : {na.mullvad_relay_country}",
        f"  mullvad killswitch : {killswitch}",
        f"  mullvad account    : {account}",
    ]
    if na.default_network_path == "clearnet":
        lines.append("  note: clearnet = no anonymising layer; re-run and pick tor/vpn to enable privacy.")
    warning = dependency_warning(na.default_network_path, tor_binary=na.tor_binary_path)
    if warning:
        lines.append(f"  {warning}")
    lines.append("  Applied at the next `hermes` session, or `hermes-mordred network use <path>` to switch now.")
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
