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
import logging
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from .._home import HERMES_BASE
from ..network import api
from ..network._exceptions import MordredNetworkError
from .configure import (
    NonInteractiveAbort,
    PromptIO,
    PromptToolkitIO,
    _RefusingPromptIO,
)
from .credentials_writer import CredentialsWriter, JSONCredentialsWriter
from .env_file_writer import DotEnvFileWriter, EnvFileWriter
from .policy_writer import PolicyWriter

_LOG = logging.getLogger("mordred.wizard.network_cli")

DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
_VALID_PATHS = ("tor", "vpn", "clearnet")

DEFAULT_TOR_SOCKS_PORT: Final[int] = 9050
MULLVAD_ACCOUNT_ENV_VAR_NAME: Final[str] = "MORDRED_MULLVAD_ACCOUNT"


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
        print(f"error: unknown network path {target!r}; choose one of {_VALID_PATHS}")
        return 2

    config_path = _resolve_config_path(args)

    try:
        _write_default_path_to_config(config_path, target)
    except OSError as e:
        print(f"error: failed to write {config_path}: {e}")
        return 3

    live = _runtime_registered()
    if not live:
        print(f"set default_path = {target!r} in {config_path}. Change is deferred to the next `hermes` session.")
        return 0

    try:
        api.use(target)  # type: ignore[arg-type]
    except MordredNetworkError as e:
        print(f"error: api.use({target!r}) failed: {e}")
        return 1
    print(f"switched to {target!r} (also persisted to {config_path}).")
    return 0


def handle_status(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network status``.

    Shows live runtime state when available, else the disk-configured
    default with a "(not active in this process)" marker so the user
    can tell whether the value they see is currently routing traffic.
    """
    config_path = _resolve_config_path(args)
    if _runtime_registered():
        s = api.status()
        ready_label = "ready" if s.ready else "not ready"
        last_health = "ok" if s.last_health else "FAILED"
        print(f"active_path = {s.active_path!r}  state = {ready_label}  last_health = {last_health}")
        if api.is_dropped():
            print(
                "  [warning] path was flagged as DROPPED by the liveness "
                "worker. Strict-mode tool calls will refuse until the path "
                "is re-bring-up'd via `hermes mordred network use <path>`."
            )
        return 0

    configured = _read_default_path_from_config(config_path)
    print(f"configured default_path = {configured!r}  (runtime not active in this process)")
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

    def to_config_yaml_section(self) -> dict[str, object]:
        """The body merged into ``plugins.mordred_network`` in config.yaml.

        Key remap: ``default_network_path`` becomes ``default_path`` on disk so
        the network reader (``mordred_hermes.network`` /
        :func:`_read_default_path_from_config`) keeps working unchanged.
        """
        return {
            "default_path": self.default_network_path,
            "tor_binary_path": self.tor_binary_path,
            "tor_socks_port": self.tor_socks_port,
            "mullvad_account_id_env": self.mullvad_account_id_env,
            "mullvad_relay_country": self.mullvad_relay_country,
            "mullvad_killswitch": self.mullvad_killswitch,
        }


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


def collect_network_answers(
    prompt_io: PromptIO,
    *,
    existing: Mapping[str, Any] | None = None,
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
    )
    tor_binary_path = prompt_io.ask_text(
        label="Tor binary path",
        default=str(existing.get("tor_binary_path") or "tor"),
    )
    tor_socks_port = _coerce_tor_socks_port(
        prompt_io.ask_text(
            label="Tor SOCKS port",
            default=str(existing.get("tor_socks_port") or DEFAULT_TOR_SOCKS_PORT),
        )
    )
    # Blank = keep the current secret (re-run safe). The label says so.
    mullvad_account_secret = prompt_io.ask_password(
        label="Mullvad account number (blank = keep current; stored in ~/.hermes/.env)",
        default="",
    )
    mullvad_relay_country = _coerce_mullvad_relay_country(
        prompt_io.ask_text(
            label="Mullvad relay country (`auto` or 2-letter code)",
            default=str(existing.get("mullvad_relay_country") or "auto"),
        )
    )
    mullvad_killswitch = prompt_io.ask_bool(
        label="Mullvad killswitch (lockdown-mode)",
        default=_coerce_seed_bool(existing.get("mullvad_killswitch", False)),
    )

    network_answers = NetworkAnswers(
        default_network_path=default_network_path,
        tor_binary_path=tor_binary_path,
        tor_socks_port=tor_socks_port,
        mullvad_account_id_env=MULLVAD_ACCOUNT_ENV_VAR_NAME,
        mullvad_relay_country=mullvad_relay_country,
        mullvad_killswitch=mullvad_killswitch,
    )
    return NetworkInitInputs(
        network_answers=network_answers,
        _mullvad_account_secret=mullvad_account_secret,
    )


def run_init(
    *,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    env_writer: EnvFileWriter,
    credentials_writer: CredentialsWriter,
    env_path: Path | None = None,
    credentials_path: Path | None = None,
) -> int:
    """Persist the collected network-privacy answers. Returns an exit code.

    Routing mirrors what ``configure`` used to do, but as a standalone,
    re-runnable command:

    - ``plugins.mordred_network`` is **merged** (not whole-replaced) into
      ``config.yaml`` so unrelated user-edited sub-fields survive.
    - A non-empty Mullvad secret goes to the :class:`EnvFileWriter`
      (``~/.hermes/.env``). A blank answer is a no-op there, keeping any
      existing secret (re-run safe) rather than stripping the line.
    - The relay/killswitch indirection goes to the :class:`CredentialsWriter`
      (``~/.hermes/mordred/credentials/network.json``).
    """
    existing = _read_existing_network_section(policy_writer.config_path)
    inputs = collect_network_answers(prompt_io, existing=existing)
    na = inputs.network_answers

    policy_writer.merge_mordred_sections({"mordred_network": na.to_config_yaml_section()})

    resolved_env_path = env_path if env_path is not None else (HERMES_BASE / ".env")
    # ``wrote_secret`` is a bool (never the plaintext), safe to hold as a local.
    # The secret itself is accessed only inline at the upsert below, so it never
    # sits in this frame's locals where --showlocals / a debugger / a rich
    # traceback could surface it (Codex review 2026-06-05). Blank secret: do NOT
    # upsert "" -- that strips the line; leave the existing .env untouched so a
    # re-run keeps the current secret.
    wrote_secret = bool(inputs._mullvad_account_secret)
    if wrote_secret:
        env_writer.upsert(
            resolved_env_path,
            key=na.mullvad_account_id_env,
            value=inputs._mullvad_account_secret,
        )

    resolved_credentials_path = (
        credentials_path if credentials_path is not None else (HERMES_BASE / "mordred" / "credentials" / "network.json")
    )
    credentials_writer.write_network(
        resolved_credentials_path,
        mullvad_account_id_env=na.mullvad_account_id_env,
        mullvad_relay_country=na.mullvad_relay_country,
        mullvad_killswitch=na.mullvad_killswitch,
    )

    print(_init_summary(na, secret_written=wrote_secret))
    return 0


def handle_init(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network init``.

    Thin CLI adapter: pick the prompt backend (real prompt_toolkit, or the
    refusing double under ``--non-interactive``) and the production writers,
    then delegate to :func:`run_init`. ``--non-interactive`` aborts with exit
    code 2 because there is no flag surface to pre-specify the answers yet.
    """
    non_interactive = bool(getattr(args, "non_interactive", False))
    config_path = _resolve_config_path(args)
    prompt_io: PromptIO = _RefusingPromptIO() if non_interactive else PromptToolkitIO()
    try:
        return run_init(
            prompt_io=prompt_io,
            policy_writer=PolicyWriter(config_path=config_path),
            env_writer=DotEnvFileWriter(),
            credentials_writer=JSONCredentialsWriter(),
        )
    except NonInteractiveAbort as e:
        print(f"hermes mordred network init: {e}", file=sys.stderr)
        return 2


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


def _init_summary(na: NetworkAnswers, *, secret_written: bool) -> str:
    """User-facing confirmation printed after a successful ``network init``.

    Echoes the resolved settings so the user can verify what was saved, and
    whether the Mullvad secret was updated or left unchanged (blank = keep).
    """
    killswitch = "enabled" if na.mullvad_killswitch else "disabled"
    account = "stored in ~/.hermes/.env" if secret_written else "unchanged"
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
    lines.append("  Applied at the next `hermes` session, or `hermes-mordred network use <path>` to switch now.")
    return "\n".join(lines)


__all__ = [
    "NetworkAnswers",
    "NetworkInitInputs",
    "collect_network_answers",
    "handle_init",
    "handle_status",
    "handle_use",
    "run_init",
]
