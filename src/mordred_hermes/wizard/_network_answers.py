"""Data model and input coercion for ``hermes mordred network init``.

Holds the pieces that carry no side effects and no prompt / IO dependency:

* :class:`NetworkAnswers` -- the env-var-only record of the six wizard outputs
  plus its ``to_config_yaml_section`` serialiser.
* :class:`NetworkInitInputs` -- the redaction-safe carrier that pairs the
  answers with the raw (never-``repr``-ed) Mullvad secret.
* the input-coercion helpers (:func:`_coerce_tor_socks_port` etc.) and the
  shell-command tokenisers (:func:`_split_cmd` / :func:`_join_cmd` /
  :func:`_seed_cmd`) that normalise hand-edited config / prompt answers.

The interactive prompt sequence that *produces* these objects lives in
:mod:`mordred_hermes.wizard._network_init`; the handlers and persistence live in
:mod:`mordred_hermes.wizard.network_cli`, which re-exports the public names
(:class:`NetworkAnswers`, ``_VALID_PATHS``) so existing imports keep working.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass, field
from typing import Final

_LOG = logging.getLogger("mordred.wizard.network_cli")

_VALID_PATHS = ("tor", "vpn", "clearnet")

DEFAULT_TOR_SOCKS_PORT: Final[int] = 9050
MULLVAD_ACCOUNT_ENV_VAR_NAME: Final[str] = "MORDRED_MULLVAD_ACCOUNT"


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
