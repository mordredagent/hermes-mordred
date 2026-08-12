"""Interactive / flag-driven answer collection for ``network init``.

This module owns the prompt sequence that turns operator input (or, in
non-interactive mode, CLI flags) into a :class:`NetworkInitInputs`. It is
deliberately free of side effects: no file writes, no ``HERMES_BASE``, no
``PromptToolkitIO`` -- those live in :mod:`mordred_hermes.wizard.network_cli`,
which calls :func:`collect_network_answers` / :func:`network_answers_from_args`
and then persists the result.

The per-prompt description strings (mirrors of the Tor / VPN tables in
``docs/user/USAGE.md``) live here next to the prompts that use
them; ``network_cli`` re-exports the handful the tests assert on.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from ._network_answers import (
    _VALID_PATHS,
    DEFAULT_TOR_SOCKS_PORT,
    MULLVAD_ACCOUNT_ENV_VAR_NAME,
    NetworkAnswers,
    NetworkInitInputs,
    _coerce_mullvad_relay_country,
    _coerce_seed_bool,
    _coerce_tor_socks_port,
    _join_cmd,
    _seed_cmd,
    _split_cmd,
)
from .configure import PromptIO

#: Inline descriptions shown next to each route in the ``network init``
#: privacy-path radio dialog (rendered as ``<route> — <description>`` by
#: ``PromptToolkitIO``). Before this each prompt opened as a bare label with no
#: hint of what it does (UX request 2026-06-15); these orient the operator the
#: same way the keyvault-init intro and the ``configure`` policy-mode
#: descriptions do. Copy condenses the "What each route is" section of
#: ``docs/user/USAGE.md`` so the wizard and the docs never drift.
_NETWORK_PATH_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "tor": "Anonymity via the Tor network — slowest; needs `tor` installed",
    "vpn": "IP privacy via any VPN — faster; Mullvad recommended (paid)",
    "clearnet": "Direct connection — no anonymity, fastest (the default)",
}

#: Help line printed above each plain-text / secret / yes-no ``network init``
#: prompt (UX request 2026-06-15). Every setting only matters for a single
#: route, so each line names its route up front. Prompts are now gated on the
#: selected privacy path (UX request 2026-08-12): a clearnet user is asked
#: only the path question and never sees the Tor or VPN prompts at all, a Tor
#: user is asked only the Tor prompts, and a VPN user is asked only the VPN
#: prompts. The three Mullvad lines within the VPN block surface only when the
#: Mullvad VPN provider is selected (the provider question is asked first), so
#: a WireGuard / custom-VPN user is never prompted for a Mullvad account number
#: (UX request 2026-06-16). Mirrors the per-prompt Tor / VPN tables in
#: ``docs/user/USAGE.md``.
_TOR_BINARY_DESCRIPTION: Final[str] = (
    "Tor route only — where the `tor` program is. Leave as `tor` if it's on your PATH."
)
_TOR_SOCKS_PORT_DESCRIPTION: Final[str] = (
    "Tor route only — local port Tor's SOCKS proxy listens on. Standard is 9050; rarely changed."
)
# The label already says "Mullvad account number", so the help line carries the
# context the label can't (paid service, where it lands) instead of restating it.
_MULLVAD_ACCOUNT_DESCRIPTION: Final[str] = (
    "VPN route only — Mullvad is a paid subscription VPN; the number is saved to ~/.hermes/.env (mode 0600)."
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
    "custom provider only — command that connects the VPN, e.g. `expressvpnctl connect` or `nordvpn connect`."
)
_CUSTOM_DOWN_DESCRIPTION: Final[str] = (
    "custom provider only — command that disconnects the VPN, e.g. `expressvpnctl disconnect` or `nordvpn disconnect`."
)
_CUSTOM_HEALTH_DESCRIPTION: Final[str] = (
    "custom provider only — optional command that reports tunnel status, e.g. `nordvpn status` (blank = none)."
)


@dataclass(frozen=True, slots=True)
class _VpnSettings:
    """Outputs of :func:`_collect_vpn_settings`: the provider choice plus the
    settings of whichever provider was picked.

    When a non-Mullvad provider is selected the Mullvad relay/killswitch carry
    the existing on-disk values (not the static defaults), so switching
    providers on a re-run never silently wipes a saved Mullvad config.
    """

    vpn_provider: str
    mullvad_account_secret: str
    mullvad_relay_country: str
    mullvad_killswitch: bool
    wireguard_config_path: str
    custom_up: tuple[str, ...]
    custom_down: tuple[str, ...]
    custom_health: tuple[str, ...]


def _vpn_settings_from_existing(existing: Mapping[str, Any]) -> _VpnSettings:
    """Seed every VPN-route field from the on-disk section, asking nothing.

    Used when the ``vpn`` route wasn't selected, so ``network init`` never
    prompts for VPN settings on a ``tor`` or ``clearnet`` run (UX request
    2026-08-12). Unlike the "switched provider" preserve block inside
    :func:`_collect_vpn_settings`, this preserves EVERYTHING — including
    ``wireguard_config_path`` and the ``custom_*`` commands — because no
    provider was actively (re-)selected here; there is nothing to blank.
    This matters because :meth:`NetworkAnswers.to_config_yaml_section` only
    emits the wireguard/custom keys when non-empty, so blanking them on a
    tor/clearnet re-run would silently drop a saved wireguard/custom config
    from ``config.yaml``.
    """
    return _VpnSettings(
        vpn_provider=str(existing.get("vpn_provider") or "mullvad"),
        mullvad_account_secret="",
        mullvad_relay_country=_coerce_mullvad_relay_country(str(existing.get("mullvad_relay_country") or "auto")),
        mullvad_killswitch=_coerce_seed_bool(existing.get("mullvad_killswitch", False)),
        wireguard_config_path=str(existing.get("wireguard_config_path") or ""),
        custom_up=_seed_cmd(existing.get("custom_up_cmd")),
        custom_down=_seed_cmd(existing.get("custom_down_cmd")),
        custom_health=_seed_cmd(existing.get("custom_health_cmd")),
    )


def _collect_vpn_settings(prompt_io: PromptIO, *, existing: Mapping[str, Any], prompt_secret: bool) -> _VpnSettings:
    """Ask which VPN provider to use, then only that provider's settings.

    The provider question is asked first so the Mullvad account / relay /
    killswitch prompts can be gated on ``vpn_provider == "mullvad"`` — a
    WireGuard or custom-VPN user is never prompted for a Mullvad account number
    (UX request 2026-06-16, now that any VPN may be used). wireguard / custom
    each surface their own prompts instead.

    Non-Mullvad providers leave the Mullvad relay/killswitch at their existing
    on-disk values so a re-run that switches providers preserves a saved Mullvad
    config; ``mullvad_account_secret`` stays ``""`` (blank = keep current).
    ``wireguard_config_path`` / ``custom_*`` intentionally start blank here
    (unlike :func:`_vpn_settings_from_existing`) and are only filled back in
    when the operator actively (re-)selects that provider below — switching
    away from a saved wireguard/custom config is an active choice this
    function must still allow.
    """
    seeded = _vpn_settings_from_existing(existing)
    vpn_provider = prompt_io.ask_choice(
        label="VPN provider",
        choices=("mullvad", "wireguard", "custom"),
        default=seeded.vpn_provider,
        descriptions=_VPN_PROVIDER_DESCRIPTIONS,
    )

    mullvad_account_secret = ""
    # Preserve any saved Mullvad config when the chosen provider isn't Mullvad.
    mullvad_relay_country = seeded.mullvad_relay_country
    mullvad_killswitch = seeded.mullvad_killswitch
    wireguard_config_path = ""
    custom_up: tuple[str, ...] = ()
    custom_down: tuple[str, ...] = ()
    custom_health: tuple[str, ...] = ()

    if vpn_provider == "mullvad":
        # Blank = keep the current secret (re-run safe). The label says so. When
        # the caller has already decided to clear the secret (``--clear-mullvad``),
        # skip the prompt entirely.
        if prompt_secret:
            mullvad_account_secret = prompt_io.ask_password(
                label="Mullvad account number (blank = keep current; stored in ~/.hermes/.env)",
                default="",
                description=_MULLVAD_ACCOUNT_DESCRIPTION,
            )
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
    elif vpn_provider == "wireguard":
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

    return _VpnSettings(
        vpn_provider=vpn_provider,
        mullvad_account_secret=mullvad_account_secret,
        mullvad_relay_country=mullvad_relay_country,
        mullvad_killswitch=mullvad_killswitch,
        wireguard_config_path=wireguard_config_path,
        custom_up=custom_up,
        custom_down=custom_down,
        custom_health=custom_health,
    )


def _collect_tor_settings(prompt_io: PromptIO, *, existing: Mapping[str, Any]) -> tuple[str, int]:
    """Ask the two Tor-route prompts: binary path, then SOCKS port.

    Only called when the operator picked the ``tor`` route (UX request
    2026-08-12); :func:`collect_network_answers` seeds these two fields
    straight from ``existing`` instead of calling this on any other route, so
    a ``vpn`` or ``clearnet`` run never sees the Tor prompts.
    """
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
    return tor_binary_path, tor_socks_port


def collect_network_answers(
    prompt_io: PromptIO,
    *,
    existing: Mapping[str, Any] | None = None,
    prompt_secret: bool = True,
) -> NetworkInitInputs:
    """Run the network-privacy prompts, seeding defaults from ``existing``.

    Prompts are gated by the selected privacy path (UX request 2026-08-12):
    the wizard always asks the path question first, then asks only the
    prompts that route needs.

    - ``clearnet`` → the path question is the only prompt; the wizard
      finishes there.
    - ``tor`` → followed by the Tor binary path and Tor SOCKS port prompts;
      the VPN provider block is never shown.
    - ``vpn`` → followed by the VPN provider question and (per
      :func:`_collect_vpn_settings`) the selected provider's own settings;
      the Tor prompts are never shown.

    Every prompt that a given route does not ask is instead seeded straight
    from ``existing`` (falling back to the static safe defaults), so a
    re-run on a different route never silently wipes settings belonging to a
    route that isn't currently selected — the same non-destructive contract
    :func:`_collect_vpn_settings` already applies one level down when a
    non-Mullvad provider is chosen (UX request 2026-06-16).

    ``existing`` is the current ``plugins.mordred_network`` body (see
    :func:`_read_existing_network_section`). Seeding each asked prompt's
    default from it makes a re-run of ``network init`` non-destructive:
    pressing Enter on every prompt keeps the on-disk value. A blank Mullvad
    answer is preserved as ``""`` so :func:`run_init` can leave any existing
    ``.env`` secret intact instead of stripping it.
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

    if default_network_path == "tor":
        tor_binary_path, tor_socks_port = _collect_tor_settings(prompt_io, existing=existing)
    else:
        tor_binary_path = str(existing.get("tor_binary_path") or "tor")
        tor_socks_port = _coerce_tor_socks_port(str(existing.get("tor_socks_port") or DEFAULT_TOR_SOCKS_PORT))

    if default_network_path == "vpn":
        vpn = _collect_vpn_settings(prompt_io, existing=existing, prompt_secret=prompt_secret)
    else:
        vpn = _vpn_settings_from_existing(existing)

    network_answers = NetworkAnswers(
        default_network_path=default_network_path,
        tor_binary_path=tor_binary_path,
        tor_socks_port=tor_socks_port,
        mullvad_account_id_env=MULLVAD_ACCOUNT_ENV_VAR_NAME,
        mullvad_relay_country=vpn.mullvad_relay_country,
        mullvad_killswitch=vpn.mullvad_killswitch,
        vpn_provider=vpn.vpn_provider,
        wireguard_config_path=vpn.wireguard_config_path,
        custom_up_cmd=vpn.custom_up,
        custom_down_cmd=vpn.custom_down,
        custom_health_cmd=vpn.custom_health,
    )
    return NetworkInitInputs(
        network_answers=network_answers,
        _mullvad_account_secret=vpn.mullvad_account_secret,
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
