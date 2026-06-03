"""Phase A acceptance tests for the wizard CLI scaffold.

Verifies that ``hermes mordred --help`` exposes every documented
subcommand (SPEC.md §Plugin: ``mordred_wizard``) and that each Phase 0
stub handler raises :class:`NotImplementedError` with the expected
"Phase X not yet landed" marker. Subsequent phases will replace each
stub-targeted test with a real behavioural test.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard import keyvault_cli, register
from mordred_hermes.wizard.cli import _setup_subparser, dispatch, main


class _CapturingContext:
    """Records the single ``register_cli_command`` invocation."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def register_cli_command(
        self,
        name: str,
        help: str,
        setup_fn: Callable[[argparse.ArgumentParser], None],
        handler_fn: Callable[[argparse.Namespace], Any] | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            {
                "name": name,
                "help": help,
                "setup_fn": setup_fn,
                "handler_fn": handler_fn,
                "description": description,
            }
        )


def _build_parser() -> argparse.ArgumentParser:
    """Build an isolated ``hermes mordred`` parser the same way Hermes would."""
    root = argparse.ArgumentParser(prog="hermes")
    sub = root.add_subparsers(dest="command")
    plugin_parser = sub.add_parser("mordred")
    _setup_subparser(plugin_parser)
    return root


class TestRegister:
    def test_register_calls_register_cli_command_once(self) -> None:
        ctx = _CapturingContext()
        register(ctx)
        assert len(ctx.calls) == 1
        call = ctx.calls[0]
        assert call["name"] == "mordred"
        assert "Mordred privacy layer" in call["help"]
        assert call["setup_fn"] is _setup_subparser
        assert call["description"]  # non-empty description for `--help` discoverability


class TestSubcommandTree:
    """Every documented subcommand must be reachable via ``argparse``."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["mordred", "configure"],
            ["mordred", "upgrade"],
            ["mordred", "upgrade", "--reset"],
            ["mordred", "upgrade", "--non-interactive"],
            ["mordred", "upgrade", "--audit-merge", "skip"],
            ["mordred", "upgrade", "--policy-conflict", "abort"],
            ["mordred", "install", "some-skill"],
            ["mordred", "network", "use", "tor"],
            ["mordred", "network", "use", "vpn"],
            ["mordred", "network", "use", "clearnet"],
            ["mordred", "network", "status"],
            ["mordred", "policy", "show"],
            ["mordred", "policy", "explain", "skill-id"],
            ["mordred", "policy", "dry-run", "/tmp/SKILL.md"],
            ["mordred", "policy", "reload"],
            ["mordred", "audit", "tail"],
            ["mordred", "audit", "tail", "-n", "5"],
            ["mordred", "audit", "grep", "policy.strict"],
            ["mordred", "audit", "decrypt", "--date", "2026-05-10"],
            ["mordred", "audit", "purge", "--before", "2026-01-01"],
            ["mordred", "keyvault", "init"],
            ["mordred", "keyvault", "list"],
            ["mordred", "keyvault", "verify-digest"],
            ["mordred", "keyvault", "recover", "--blob", "/tmp/x"],
            ["mordred", "vault", "migrate"],
            ["mordred", "vault", "migrate", "/tmp/.env", "/tmp/config.yaml"],
            ["mordred", "vault", "migrate", "--root", "/tmp/vault"],
            ["mordred", "plugins", "list"],
        ],
    )
    def test_argv_parses_and_wires_a_handler(self, argv: list[str]) -> None:
        parser = _build_parser()
        ns = parser.parse_args(argv)
        assert hasattr(ns, "func"), f"set_defaults(func=...) missing for {argv!r}"


class TestUpgradeFlagShape:
    """The H5 conflict-resolution flags must accept their documented choices."""

    def test_audit_merge_choices(self) -> None:
        parser = _build_parser()
        for choice in ("skip", "append-all", "abort"):
            ns = parser.parse_args(["mordred", "upgrade", "--audit-merge", choice])
            assert ns.audit_merge == choice

    def test_audit_merge_rejects_unknown_choice(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["mordred", "upgrade", "--audit-merge", "bogus"])

    def test_policy_conflict_choices(self) -> None:
        parser = _build_parser()
        for choice in ("keep-existing", "overwrite", "abort"):
            ns = parser.parse_args(["mordred", "upgrade", "--policy-conflict", choice])
            assert ns.policy_conflict == choice


class TestDispatchWithoutFunc:
    """Defensive: dispatch on a Namespace lacking ``func`` exits cleanly."""

    def test_missing_func_raises_systemexit(self) -> None:
        with pytest.raises(SystemExit):
            dispatch(argparse.Namespace())


class TestMainStandaloneEntry:
    """`hermes-mordred` console-script entry (Codex P1 workaround for Hermes 0.11)."""

    def test_help_exits_cleanly(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "configure" in out
        assert "upgrade" in out
        assert "policy" in out

    def test_no_args_shows_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main([])
        # argparse exits with code 2 on missing required subcommand
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "COMMAND" in err or "required" in err.lower()

    def test_unknown_subcommand_argparse_exits_cleanly(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["bogus-subcommand"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "invalid choice" in err


class TestEnableSEWiring:
    """``hermes mordred keyvault enable-se`` parser wiring + adapter."""

    def test_enable_se_parses_and_wires_handler(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-se"])
        assert hasattr(ns, "func"), "set_defaults(func=...) missing for keyvault enable-se"

    def test_enable_se_flags_parse(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-se", "--install-dir", "/tmp/bin", "--unattended"])
        assert ns.install_dir == "/tmp/bin"
        assert ns.unattended is True

    def test_cli_enable_se_forwards_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_se(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "enable_se", _fake_enable_se)
        ns = argparse.Namespace(install_dir="/tmp/bin", unattended=True)
        rc = keyvault_cli.cli_enable_se(ns)
        assert rc == 0
        assert captured["install_dir"] == Path("/tmp/bin")
        assert captured["unattended"] is True

    def test_cli_enable_se_absent_flags_pass_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_se(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "enable_se", _fake_enable_se)
        ns = argparse.Namespace(install_dir=None, unattended=False)
        keyvault_cli.cli_enable_se(ns)
        assert captured["install_dir"] is None
        assert captured["unattended"] is None  # absence → env default, not False


class TestEnableTPMWiring:
    """``hermes mordred keyvault enable-tpm`` parser wiring + adapter (v2-OS2 2c).

    The TPM is Tier 2 (machine-bound), so ``enable-tpm`` exposes only
    ``--install-dir`` — there is deliberately no ``--unattended`` per-use gate.
    """

    def test_enable_tpm_parses_and_wires_handler(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-tpm"])
        assert hasattr(ns, "func"), "set_defaults(func=...) missing for keyvault enable-tpm"

    def test_enable_tpm_install_dir_parses(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-tpm", "--install-dir", "/tmp/bin"])
        assert ns.install_dir == "/tmp/bin"

    def test_enable_tpm_rejects_unattended_flag(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["mordred", "keyvault", "enable-tpm", "--unattended"])

    def test_cli_enable_tpm_forwards_install_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_tpm(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "enable_tpm", _fake_enable_tpm)
        ns = argparse.Namespace(install_dir="/tmp/bin")
        rc = keyvault_cli.cli_enable_tpm(ns)
        assert rc == 0
        assert captured["install_dir"] == Path("/tmp/bin")
        assert "unattended" not in captured  # Tier 2: no per-use gate

    def test_cli_enable_tpm_absent_install_dir_passes_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_tpm(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "enable_tpm", _fake_enable_tpm)
        ns = argparse.Namespace(install_dir=None)
        keyvault_cli.cli_enable_tpm(ns)
        assert captured["install_dir"] is None
