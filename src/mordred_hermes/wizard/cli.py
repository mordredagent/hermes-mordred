"""argparse subparser tree for ``hermes mordred ...``.

Phase A (1.3) ships the full command surface so that ``hermes mordred --help``
already lists every subcommand. Each handler delegates to its own module
(populated phase-by-phase). Subcommands whose modules are not implemented
yet raise :class:`NotImplementedError` from a stable error message —
``hermes mordred network status`` returns a clear "deferred to Phase 3"
message rather than ``argparse: invalid choice``.

Subcommand tree (SPEC.md §Plugin: ``mordred_wizard`` L386-407):

- ``configure``                              — Phase C / TODO §1.3 L172
- ``upgrade [--reset|--non-interactive|...]``— Phase E / TODO §1.3 L173
- ``install <skill>``                        — Phase F (delegates to privacy_check)
- ``network {use,status} [path]``            — Phase 3 stub
- ``policy {show,explain,dry-run,reload}``   — Phase D / TODO §1.3 L185
- ``audit {tail,grep,decrypt,purge}``        — Phase F (decrypt/purge: Phase 4)
- ``keyvault {init,list,verify-digest,recover}`` — Phase 4 stub
- ``plugins list``                           — Phase F (closes §0.5 L128 UX gap)
"""

from __future__ import annotations

import argparse
from typing import Any


def _setup_subparser(parser: argparse.ArgumentParser) -> None:
    """Build the full ``hermes mordred`` subcommand tree.

    Hermes calls this once at CLI initialisation with the top-level
    ``mordred`` subparser. We add ``mordred_command`` dest and per-command
    sub-subparsers, each wired via ``set_defaults(func=<handler>)``.
    """
    sub = parser.add_subparsers(dest="mordred_command", required=True, metavar="COMMAND")

    _add_configure(sub)
    _add_upgrade(sub)
    _add_install(sub)
    _add_network(sub)
    _add_policy(sub)
    _add_audit(sub)
    _add_keyvault(sub)
    _add_vault(sub)
    _add_plugins(sub)


# -----------------------------------------------------------------------------
# Subcommand parsers — each calls set_defaults(func=...) wiring its handler.
# -----------------------------------------------------------------------------


def _add_configure(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "configure",
        help="Run interactive Mordred setup (writes config.yaml + policy.json)",
    )
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail fast on any prompt (CI / scripted use)",
    )
    p.set_defaults(func=_handle_configure)


def _add_upgrade(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "upgrade",
        help="Idempotent migration (Story 1 / Story 1.5). Detects ~/.openclaw if present.",
    )
    p.add_argument("--reset", action="store_true", help="Force overwrite on every conflict")
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail fast when a conflict policy was not pre-specified",
    )
    p.add_argument(
        "--audit-merge",
        choices=["skip", "append-all", "abort"],
        help="OpenClaw audit-log merge policy when overlap is detected",
    )
    p.add_argument(
        "--policy-conflict",
        choices=["keep-existing", "overwrite", "abort"],
        help="Behaviour when ~/.hermes/config.yaml plugins.mordred_* already differs",
    )
    p.set_defaults(func=_handle_upgrade)


def _add_install(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "install",
        help="Install a skill through the Mordred policy gate (delegates to privacy_check)",
    )
    p.add_argument("skill", help="Skill name or path to a directory containing SKILL.md")
    p.set_defaults(func=_handle_install)


def _add_network(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("network", help="Network path control (Phase 3)")
    nsub = p.add_subparsers(dest="network_command", required=True, metavar="COMMAND")

    p_use = nsub.add_parser("use", help="Switch active network path")
    p_use.add_argument("path", choices=["tor", "vpn", "clearnet"])
    p_use.set_defaults(func=_handle_network_use)

    p_status = nsub.add_parser("status", help="Show active path and liveness")
    p_status.set_defaults(func=_handle_network_status)


def _add_policy(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("policy", help="Inspect and explain the active Mordred policy")
    psub = p.add_subparsers(dest="policy_command", required=True, metavar="COMMAND")

    p_show = psub.add_parser("show", help="Print resolved policy.json")
    p_show.set_defaults(func=_handle_policy_show)

    p_explain = psub.add_parser("explain", help="Explain the install decision for a known skill id")
    p_explain.add_argument("skill_id")
    p_explain.set_defaults(func=_handle_policy_explain)

    p_dry = psub.add_parser("dry-run", help="Evaluate install policy against a SKILL.md path without installing")
    p_dry.add_argument("skill_path")
    p_dry.set_defaults(func=_handle_policy_dry_run)

    p_reload = psub.add_parser("reload", help="Re-read policy from config.yaml (in-process state reset)")
    p_reload.set_defaults(func=_handle_policy_reload)


def _add_audit(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("audit", help="Tail / grep / decrypt the Mordred audit log")
    asub = p.add_subparsers(dest="audit_command", required=True, metavar="COMMAND")

    p_tail = asub.add_parser("tail", help="Tail the most recent audit entries")
    p_tail.add_argument("-n", "--lines", type=int, default=20)
    p_tail.set_defaults(func=_handle_audit_tail)

    p_grep = asub.add_parser("grep", help="Grep audit entries (line-wise regex)")
    p_grep.add_argument("pattern")
    p_grep.set_defaults(func=_handle_audit_grep)

    p_decrypt = asub.add_parser("decrypt", help="Decrypt encrypted audit entries (Phase 4)")
    p_decrypt.add_argument("--date", required=True, help="YYYY-MM-DD")
    p_decrypt.set_defaults(func=_handle_audit_decrypt)

    p_purge = asub.add_parser("purge", help="Manually purge pre-Phase-4 plaintext entries (Phase 4)")
    p_purge.add_argument("--before", required=True, help="YYYY-MM-DD")
    p_purge.set_defaults(func=_handle_audit_purge)


def _add_keyvault(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("keyvault", help="Mordred keyvault management (Phase 4)")
    ksub = p.add_subparsers(dest="keyvault_command", required=True, metavar="COMMAND")

    p_init = ksub.add_parser("init", help="Initialise the keyvault")
    p_init.add_argument(
        "--store-seed-for-hd",
        action="store_true",
        help="SE-encrypt the generated seed so HD Ethereum accounts can be derived later "
        "(Option A: seed stored at rest; default is paper-only).",
    )
    p_init.set_defaults(func=_handle_keyvault_init)
    ksub.add_parser("list", help="List key IDs").set_defaults(func=_handle_keyvault_list)
    ksub.add_parser("verify-digest", help="Verify the keyvault digest").set_defaults(
        func=_handle_keyvault_verify_digest
    )
    p_recover = ksub.add_parser("recover", help="Restore from a backup blob")
    p_recover.add_argument("--blob", required=True)
    p_recover.set_defaults(func=_handle_keyvault_recover)
    p_enable_se = ksub.add_parser(
        "enable-se",
        help="Build + install the hardware Secure Enclave helper (ad-hoc signed; no Apple Developer account)",
    )
    p_enable_se.add_argument("--install-dir", help="Install directory for the helper (default: ~/.local/bin)")
    p_enable_se.add_argument(
        "--unattended",
        action="store_true",
        help="Create an unattended SE key (decrypt runs without a Touch ID prompt while the session is unlocked)",
    )
    p_enable_se.set_defaults(func=_handle_keyvault_enable_se)
    p_enable_tpm = ksub.add_parser(
        "enable-tpm",
        help="Build + install the Linux TPM 2.0 helper (machine-bound; Tier 2, no per-use prompt)",
    )
    p_enable_tpm.add_argument("--install-dir", help="Install directory for the helper (default: ~/.local/bin)")
    p_enable_tpm.set_defaults(func=_handle_keyvault_enable_tpm)


def _add_vault(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("vault", help="At-rest secrets/env vault")
    vsub = p.add_subparsers(dest="vault_command", required=True, metavar="COMMAND")

    p_init = vsub.add_parser(
        "init",
        help="Create a new encrypted vault sealed under a recovery passphrase",
    )
    p_init.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_init.set_defaults(func=_handle_vault_init)

    p_add = vsub.add_parser(
        "add",
        help="Encrypt a file into the vault under a logical name",
    )
    p_add.add_argument("name", help="Logical name to store the file under (e.g. .env)")
    p_add.add_argument("source", help="Path to the plaintext file to encrypt into the vault")
    p_add.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_add.set_defaults(func=_handle_vault_add)

    p_status = vsub.add_parser(
        "status",
        help="Show a vault's generation and enrolled file names (opens read-only via passphrase recovery)",
    )
    p_status.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_status.set_defaults(func=_handle_vault_status)

    p_cat = vsub.add_parser(
        "cat",
        help="Print one enrolled file's decrypted bytes to stdout (opens read-only via passphrase recovery)",
    )
    p_cat.add_argument("name", help="Enrolled file name to decrypt and print")
    p_cat.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_cat.set_defaults(func=_handle_vault_cat)

    p_migrate = vsub.add_parser(
        "migrate",
        help="Import existing plaintext files into the vault (default: .env + config.yaml under the Hermes home)",
    )
    p_migrate.add_argument(
        "source",
        nargs="*",
        help="Plaintext file(s) to import, each enrolled under its basename "
        "(default: .env and config.yaml under the Hermes home)",
    )
    p_migrate.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_migrate.set_defaults(func=_handle_vault_migrate)

    p_set_memory_key = vsub.add_parser(
        "set-memory-key",
        help="Store/rotate HERMES_MEMORY_KEY in the vault .env so Hermes can encrypt agent memory at rest",
    )
    p_set_memory_key.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_set_memory_key.add_argument(
        "--rotate",
        action="store_true",
        help="Replace an existing key with a fresh one (default: leave an existing key unchanged)",
    )
    p_set_memory_key.set_defaults(func=_handle_vault_set_memory_key)

    p_enable_cfg = vsub.add_parser(
        "enable-config-decrypt",
        help="Put config.yaml under the at-rest vault (transparent decrypt at Hermes startup, v2-F8)",
    )
    p_enable_cfg.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_enable_cfg.set_defaults(func=_handle_vault_enable_config_decrypt)

    p_disable_cfg = vsub.add_parser(
        "disable-config-decrypt",
        help="Stop managing config.yaml in the vault and restore a plaintext copy (recovery)",
    )
    p_disable_cfg.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_disable_cfg.set_defaults(func=_handle_vault_disable_config_decrypt)


def _add_plugins(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "plugins",
        help="List Mordred plugins (closes the entry-point discovery gap, §0.5 L128)",
    )
    psub = p.add_subparsers(dest="plugins_command", required=True, metavar="COMMAND")
    psub.add_parser("list", help="List discovered Mordred plugins").set_defaults(func=_handle_plugins_list)


# -----------------------------------------------------------------------------
# Handlers — Phase A stubs. Subsequent phases swap each body for the real impl.
# Each handler accepts ``argparse.Namespace`` and returns an exit code (int).
# -----------------------------------------------------------------------------


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
    upgrade.run(options=options, policy_writer=PolicyWriter())
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


def _handle_keyvault_recover(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_recover(args)


def _handle_keyvault_enable_se(args: argparse.Namespace) -> int:
    from . import keyvault_native_cli

    return keyvault_native_cli.cli_enable_se(args)


def _handle_keyvault_enable_tpm(args: argparse.Namespace) -> int:
    from . import keyvault_native_cli

    return keyvault_native_cli.cli_enable_tpm(args)


def _handle_vault_init(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_init(args)


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
    from . import vault_cli

    return vault_cli.cli_set_memory_key(args)


def _handle_vault_enable_config_decrypt(args: argparse.Namespace) -> int:
    from . import config_decrypt_cli

    return config_decrypt_cli.cli_enable(args)


def _handle_vault_disable_config_decrypt(args: argparse.Namespace) -> int:
    from . import config_decrypt_cli

    return config_decrypt_cli.cli_disable(args)


def _handle_plugins_list(args: argparse.Namespace) -> int:
    from . import plugins_list

    return plugins_list.cli_handler(args)


def dispatch(args: argparse.Namespace) -> int:
    """Top-level dispatch helper.

    Hermes calls the handler set via ``set_defaults(func=...)`` directly,
    so this helper is mainly for tests that build a Namespace by hand.
    Returns the handler's exit code (0 = success). Re-raises
    :class:`NotImplementedError` from stub handlers so tests can assert
    on the deferred-phase message.
    """
    func = getattr(args, "func", None)
    if func is None:
        raise SystemExit("usage: hermes mordred <COMMAND> ... (no subcommand provided)")
    result: Any = func(args)
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
    parser = argparse.ArgumentParser(
        prog="hermes-mordred",
        description=(
            "Mordred privacy layer (standalone CLI). "
            "Same subcommand tree as `hermes mordred ...` once Hermes 0.12+ wires it."
        ),
    )
    _setup_subparser(parser)
    ns = parser.parse_args(argv)
    return dispatch(ns)
