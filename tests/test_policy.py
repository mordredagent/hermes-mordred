"""Matrix tests for the pure policy evaluator.

Covers TODO §1.4 / PLAN §1.4: strict/lenient/off x clearnet/tor/vpn/local-only/missing.
"""

from __future__ import annotations

import pytest

from mordred_hermes.privacy_check.policy import (
    PolicyOutcome,
    evaluate_install,
    evaluate_pre_tool_call,
)


class TestEvaluateInstall:
    @pytest.mark.parametrize(
        ("policy_mode", "network_req", "expected"),
        [
            ("strict", "vpn", PolicyOutcome("allow", None)),
            ("strict", "local-only", PolicyOutcome("allow", None)),
        ],
    )
    def test_matrix(self, policy_mode: str, network_req: str | None, expected: PolicyOutcome) -> None:
        result = evaluate_install(
            policy_mode=policy_mode,  # type: ignore[arg-type]
            network_requirements=network_req,  # type: ignore[arg-type]
        )
        assert result == expected


class TestEvaluateInstallKeyvault:
    """``metadata.mordred.requires_keyvault`` opt-in enforcement (TODO §4.1)."""

    @pytest.mark.parametrize(
        ("policy_mode", "network_req", "keyvault_initialized", "expected"),
        [
            ("lenient", "tor", True, PolicyOutcome("allow", None)),
        ],
    )
    def test_requires_keyvault_matrix(
        self,
        policy_mode: str,
        network_req: str,
        keyvault_initialized: bool,
        expected: PolicyOutcome,
    ) -> None:
        result = evaluate_install(
            policy_mode=policy_mode,  # type: ignore[arg-type]
            network_requirements=network_req,  # type: ignore[arg-type]
            requires_keyvault=True,
            keyvault_initialized=keyvault_initialized,
        )
        assert result == expected

    @pytest.mark.parametrize(
        "policy_mode",
        [
            "strict",
            "lenient",
        ],
    )
    @pytest.mark.parametrize(
        "keyvault_initialized",
        [
            False,
        ],
    )
    def test_keyvault_flag_ignored_when_skill_does_not_opt_in(
        self, policy_mode: str, keyvault_initialized: bool
    ) -> None:
        """``requires_keyvault=False``: the keyvault flag must not change the decision."""
        result = evaluate_install(
            policy_mode=policy_mode,  # type: ignore[arg-type]
            network_requirements="tor",
            requires_keyvault=False,
            keyvault_initialized=keyvault_initialized,
        )
        assert result == PolicyOutcome("allow", None)

    def test_network_block_short_circuits_keyvault_check(self) -> None:
        """A strict clearnet block is returned before the keyvault check runs."""
        result = evaluate_install(
            policy_mode="strict",
            network_requirements="clearnet",
            requires_keyvault=True,
            keyvault_initialized=False,
        )
        assert result == PolicyOutcome("block", "policy.strict.clearnet")

    def test_strict_missing_metadata_short_circuits_keyvault_check(self) -> None:
        result = evaluate_install(
            policy_mode="strict",
            network_requirements=None,
            requires_keyvault=True,
            keyvault_initialized=False,
        )
        assert result == PolicyOutcome("block", "policy.strict.unknown_metadata")

    def test_lenient_keyvault_warn_wins_over_network_warn(self) -> None:
        """lenient + missing network metadata + uninitialized keyvault -> the keyvault warn reason."""
        result = evaluate_install(
            policy_mode="lenient",
            network_requirements=None,
            requires_keyvault=True,
            keyvault_initialized=False,
        )
        assert result == PolicyOutcome("warn", "policy.lenient.keyvault_uninitialized_warning")


class TestEvaluatePreToolCall:
    @pytest.mark.parametrize("blocked_tool", ["web_fetch", "web_search"])
    def test_strict_clearnet_blocks_default_blocklist(self, blocked_tool: str) -> None:
        result = evaluate_pre_tool_call(
            policy_mode="strict",
            tool_name=blocked_tool,
            active_path="clearnet",
        )
        assert result == PolicyOutcome("block", "policy.strict.clearnet")

    def test_custom_blocklist_overrides_default(self) -> None:
        custom = frozenset({"shell"})
        # Default-blocked tool no longer blocked
        assert evaluate_pre_tool_call(
            policy_mode="strict",
            tool_name="web_fetch",
            active_path="clearnet",
            blocklist=custom,
        ) == PolicyOutcome("allow", None)
        # Custom-blocked tool now blocked
        assert evaluate_pre_tool_call(
            policy_mode="strict",
            tool_name="shell",
            active_path="clearnet",
            blocklist=custom,
        ) == PolicyOutcome("block", "policy.strict.clearnet")
