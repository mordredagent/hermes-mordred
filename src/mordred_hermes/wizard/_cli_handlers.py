"""Per-command handlers for the ``hermes mordred ...`` subcommand tree.

Each ``_handle_*`` function is a thin adapter: it accepts the parsed
``argparse.Namespace`` and returns an exit code (int), delegating the real
work to its own module (lazy-imported to keep CLI start fast). Extracted from
:mod:`._cli_parsers` (which builds the subparser tree and wires these via
``set_defaults(func=...)``) to keep each module under the size guideline.
"""

from __future__ import annotations

import argparse


def _handle_status(args: argparse.Namespace) -> int:
    from . import status_cli

    return status_cli.cli_status(args)


def _handle_setup(args: argparse.Namespace) -> int:
    from . import setup_cli

    return setup_cli.cli_setup(args)


def _handle_configure(args: argparse.Namespace) -> int:
    from . import configure

    return configure.cli_handler(args)


def _handle_upgrade(args: argparse.Namespace) -> int:
    from . import upgrade
    from .policy_writer import PolicyWriter

    options = upgrade.UpgradeOptions(
        reset=bool(getattr(args, "reset", False)),
        non_interactive=bool(getattr(args, "non_interactive", False)),
        audit_merge=getattr(args, "audit_merge", None),
        policy_conflict=getattr(args, "policy_conflict", None),
    )
    report = upgrade.run(options=options, policy_writer=PolicyWriter())
    print(upgrade.render_report(report))
    return 0


def _handle_install(args: argparse.Namespace) -> int:
    from . import install_dispatch

    return install_dispatch.cli_handler(args)


def _handle_network_use(args: argparse.Namespace) -> int:
    from . import network_cli

    return network_cli.handle_use(args)


def _handle_network_status(args: argparse.Namespace) -> int:
    from . import network_cli

    return network_cli.handle_status(args)


def _handle_network_init(args: argparse.Namespace) -> int:
    from . import network_cli

    return network_cli.handle_init(args)


def _handle_policy_show(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_show(args)


def _handle_policy_explain(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_explain(args)


def _handle_policy_dry_run(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_dry_run(args)


def _handle_policy_reload(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_reload(args)


def _handle_audit_tail(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_tail(args)


def _handle_audit_grep(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_grep(args)


def _handle_audit_decrypt(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_decrypt(args)


def _handle_audit_purge(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_purge(args)


def _handle_keyvault_init(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_init(args)


def _handle_keyvault_list(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_list(args)


def _handle_keyvault_verify_digest(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_verify_digest(args)


def _handle_keyvault_export(args: argparse.Namespace) -> int:
    from . import keyvault_export_cli

    return keyvault_export_cli.cli_export(args)


def _handle_keyvault_recover(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_recover(args)


def _handle_keyvault_reset(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_reset(args)


def _handle_keyvault_enable_se(args: argparse.Namespace) -> int:
    from . import keyvault_native_cli

    return keyvault_native_cli.cli_enable_se(args)


def _handle_keyvault_enable_tpm(args: argparse.Namespace) -> int:
    from . import keyvault_native_cli

    return keyvault_native_cli.cli_enable_tpm(args)


def _handle_vault_init(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_init(args)


def _handle_vault_change_passphrase(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_change_passphrase(args)


def _handle_vault_recover(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_recover(args)


def _handle_vault_add(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_add(args)


def _handle_vault_status(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_status(args)


def _handle_vault_cat(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_cat(args)


def _handle_vault_migrate(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_migrate(args)


def _handle_vault_set_memory_key(args: argparse.Namespace) -> int:
    from . import vault_memory_key

    return vault_memory_key.cli_set_memory_key(args)


def _handle_vault_enable_config_decrypt(args: argparse.Namespace) -> int:
    from . import config_decrypt_cli

    return config_decrypt_cli.cli_enable(args)


def _handle_vault_disable_config_decrypt(args: argparse.Namespace) -> int:
    from . import config_decrypt_cli

    return config_decrypt_cli.cli_disable(args)


def _handle_encryption_status(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_status(args)


def _handle_encryption_enable(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_enable(args)


def _handle_encryption_disable(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_disable(args)


def _handle_encryption_purge(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_purge(args)


def _handle_plugins_list(args: argparse.Namespace) -> int:
    from . import plugins_list

    return plugins_list.cli_handler(args)


def _handle_extension_pair(args: argparse.Namespace) -> int:
    from . import extension_pair_cli

    return extension_pair_cli.cli_extension_pair(args)


def _handle_extension_serve(args: argparse.Namespace) -> int:
    # The extension package and launcher are dependency-light. ``serve`` owns
    # the optional aiohttp check so unrelated import bugs are never relabelled
    # as a missing ``extension`` extra here.
    from mordred_hermes.extension.__main__ import serve

    return serve(host=args.host, port=args.port)
