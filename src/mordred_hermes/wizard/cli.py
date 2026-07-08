"""Console-script entry points for ``hermes mordred ...`` / ``hermes-mordred ...``.

The argparse subcommand tree and its per-command handlers live in
:mod:`._cli_parsers` (extracted to keep this module small). This module holds
the two entry points — :func:`main` (the ``hermes-mordred`` console script,
wired in ``pyproject.toml`` ``[project.scripts]``) and :func:`dispatch` (the
handler-invocation helper Hermes / tests call) — and re-exports
``_setup_subparser`` plus the ``_handle_*`` handlers so existing import paths
are unchanged (``wizard/__init__.py`` registers ``cli._setup_subparser`` with
Hermes; tests import ``cli._setup_subparser`` / ``cli.dispatch`` / ``cli.main``
and reference ``cli._handle_*`` directly).

Subcommand tree (SPEC.md §Plugin: ``mordred_wizard``):

- ``configure``                                  — interactive Mordred setup (policy / LLM / harness)
- ``upgrade [--reset|--non-interactive|...]``    — idempotent migration (detects ~/.openclaw)
- ``install <skill>``                            — install a skill through the policy gate
- ``network {use,status,init}``                  — network-privacy path control + on-demand setup
- ``policy {show,explain,dry-run,reload}``       — inspect / explain the active policy
- ``audit {tail,grep,decrypt,purge}``            — read / maintain the audit log
- ``keyvault {init,list,verify-digest,recover,reset,enable-se,enable-tpm,eth}`` — keyvault management
- ``vault {init,add,status,cat,migrate,...}``    — at-rest secrets/env vault
- ``plugins list``                               — list discovered Mordred plugins
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from . import _term

# The subcommand tree + handlers live in ``_cli_parsers``; re-export them so
# ``cli._setup_subparser`` (Hermes registration in ``wizard/__init__.py``) and
# ``cli._handle_*`` (tests) keep resolving here. See ``__all__``.
from ._cli_parsers import (
    _add_audit,
    _add_configure,
    _add_encryption,
    _add_extension,
    _add_install,
    _add_keyvault,
    _add_network,
    _add_plugins,
    _add_policy,
    _add_status,
    _add_upgrade,
    _add_vault,
    _handle_audit_decrypt,
    _handle_audit_grep,
    _handle_audit_purge,
    _handle_audit_tail,
    _handle_configure,
    _handle_encryption_disable,
    _handle_encryption_enable,
    _handle_encryption_purge,
    _handle_encryption_status,
    _handle_extension_pair,
    _handle_install,
    _handle_keyvault_enable_se,
    _handle_keyvault_enable_tpm,
    _handle_keyvault_init,
    _handle_keyvault_list,
    _handle_keyvault_recover,
    _handle_keyvault_reset,
    _handle_keyvault_verify_digest,
    _handle_network_init,
    _handle_network_status,
    _handle_network_use,
    _handle_plugins_list,
    _handle_policy_dry_run,
    _handle_policy_explain,
    _handle_policy_reload,
    _handle_policy_show,
    _handle_status,
    _handle_upgrade,
    _handle_vault_add,
    _handle_vault_cat,
    _handle_vault_change_passphrase,
    _handle_vault_disable_config_decrypt,
    _handle_vault_enable_config_decrypt,
    _handle_vault_init,
    _handle_vault_migrate,
    _handle_vault_recover,
    _handle_vault_set_memory_key,
    _handle_vault_status,
    _setup_subparser,
)
from ._prompt_io import NonInteractiveAbort

__all__ = [
    "_add_audit",
    "_add_configure",
    "_add_encryption",
    "_add_extension",
    "_add_install",
    "_add_keyvault",
    "_add_network",
    "_add_plugins",
    "_add_policy",
    "_add_status",
    "_add_upgrade",
    "_add_vault",
    "_handle_audit_decrypt",
    "_handle_audit_grep",
    "_handle_audit_purge",
    "_handle_audit_tail",
    "_handle_configure",
    "_handle_encryption_disable",
    "_handle_encryption_enable",
    "_handle_encryption_purge",
    "_handle_encryption_status",
    "_handle_extension_pair",
    "_handle_install",
    "_handle_keyvault_enable_se",
    "_handle_keyvault_enable_tpm",
    "_handle_keyvault_init",
    "_handle_keyvault_list",
    "_handle_keyvault_recover",
    "_handle_keyvault_reset",
    "_handle_keyvault_verify_digest",
    "_handle_network_init",
    "_handle_network_status",
    "_handle_network_use",
    "_handle_plugins_list",
    "_handle_policy_dry_run",
    "_handle_policy_explain",
    "_handle_policy_reload",
    "_handle_policy_show",
    "_handle_status",
    "_handle_upgrade",
    "_handle_vault_add",
    "_handle_vault_cat",
    "_handle_vault_change_passphrase",
    "_handle_vault_disable_config_decrypt",
    "_handle_vault_enable_config_decrypt",
    "_handle_vault_init",
    "_handle_vault_migrate",
    "_handle_vault_recover",
    "_handle_vault_set_memory_key",
    "_handle_vault_status",
    "_setup_subparser",
    "dispatch",
    "main",
]


def dispatch(args: argparse.Namespace) -> int:
    """Top-level dispatch helper.

    Hermes calls the handler set via ``set_defaults(func=...)`` directly,
    so this helper is mainly for tests that build a Namespace by hand.
    Returns the handler's exit code (0 = success).

    A ``KeyboardInterrupt`` from any handler — the prompt layer re-raises it
    on Ctrl-C by design (see ``_prompt_io``) — becomes a clean ``Aborted.``
    on stderr with exit code 130 (128 + SIGINT), not a traceback. Likewise
    :class:`NonInteractiveAbort` becomes an ``error:`` line with exit code 2
    (the usage-error convention shared with ``encryption purge`` / ``audit``).

    Scope note (review 2026-07-07): this guard protects the standalone
    ``hermes-mordred`` entry (``main`` routes through here). The Hermes-native
    ``hermes mordred …`` path calls ``args.func(args)`` itself, bypassing this
    helper — when Hermes 0.12+ wires that path, it needs the same guard at the
    registration boundary (or to route through ``dispatch``).
    """
    func = getattr(args, "func", None)
    if func is None:
        raise SystemExit("usage: hermes-mordred <COMMAND> ... (no subcommand provided)")
    try:
        result: Any = func(args)
    except KeyboardInterrupt:
        # The leading newline moves past the ``^C`` the terminal echoes onto
        # the prompt line, so ``Aborted.`` starts on its own line.
        print("\nAborted.", file=sys.stderr)
        return 130
    except NonInteractiveAbort as exc:
        _term.emit_error(str(exc))
        return 2
    return int(result) if isinstance(result, int) else 0


def main(argv: list[str] | None = None) -> int:
    """Standalone ``hermes-mordred`` console-script entry.

    This is the v1 user-facing CLI. It exists because Hermes 0.11.0 does
    not iterate ``PluginManager._cli_commands`` when building its top-level
    argparse subparsers (see ``hermes_cli/main.py:9728-9740`` -- only
    ``plugins.memory.discover_plugin_cli_commands`` is consulted), so the
    wizard's ``ctx.register_cli_command("mordred", ...)`` call alone is
    silently dropped from argparse. Users invoke ``hermes-mordred ...``
    today; once Hermes 0.12+ ships entry-point CLI wiring,
    ``hermes mordred ...`` will also work via the same handlers.

    Wired in ``pyproject.toml`` ``[project.scripts]`` as
    ``hermes-mordred = "mordred_hermes.wizard.cli:main"``.
    """
    from ..__about__ import __version__

    parser = argparse.ArgumentParser(
        prog="hermes-mordred",
        description=(
            "Mordred privacy layer (standalone CLI). "
            "Same subcommand tree as `hermes mordred ...` once Hermes 0.12+ wires it."
        ),
        epilog=(
            "Quickstart (first run, in order):\n"
            "  hermes-mordred configure              interactive setup (policy / LLM / harness)\n"
            "  hermes-mordred network init           optional: Tor / VPN / clearnet privacy path\n"
            "  hermes-mordred keyvault init          create the hardware-backed keyvault\n"
            "  hermes-mordred encryption enable env  turn on at-rest encryption (first run creates the vault)\n"
            "  hermes-mordred status                 check the result at a glance\n"
            "\n"
            "Storage commands, from high- to low-level:\n"
            "  encryption  the recommended on/off switch for at-rest encryption\n"
            "              (env / config / memory / workspace)\n"
            "  keyvault    hardware-backed key management (Secure Enclave / TPM)\n"
            "  vault       the underlying encrypted file store (advanced; driven\n"
            "              by `encryption` — rarely used directly)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured output (equivalent to setting NO_COLOR=1)",
    )
    # Standalone: a bare `hermes-mordred` is a discovery moment, so the subcommand
    # is optional here and we print the quickstart help below. Hermes keeps it
    # required via the default.
    _setup_subparser(parser, required=False)
    ns = parser.parse_args(argv)
    if getattr(ns, "no_color", False):
        # Flip the env var the shared `_term.should_color()` gate already honours,
        # so the flag reaches every command's renderer without threading a param.
        os.environ["NO_COLOR"] = "1"
    if getattr(ns, "mordred_command", None) is None:
        parser.print_help()
        return 0
    return dispatch(ns)
