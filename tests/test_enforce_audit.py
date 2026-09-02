"""Audit-reason-code emission tests for ``mordred_hermes.llm_guard.enforce``.

Where ``test_enforce.py`` covers the decision matrix at a behavioural
level (raises / does-not-raise / probe routed), this file pins down the
exact ``reason`` and ``decision`` values written to the audit log on each
strict-mode path. Reasons must match the POLICY.md §Audit log reason enum
(frozen 12 codes).

This file deliberately has no overlap with ``test_enforce.py`` aside from
shared fixtures — it focuses solely on the audit-shape contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.llm_guard import enforce
from mordred_hermes.llm_guard._exceptions import MordredSessionRefused

from ._helpers import FakeAuditWriter as _FakeAuditWriter


def _noop_probe(_endpoint: str) -> None:
    return None


def _write_policy_json(
    tmp_path: Path,
    *,
    allow_cloud_llm: bool = False,
    cloud_provider_allowlist: tuple[str, ...] = (),
) -> Path:
    body = {
        "policy": "strict",
        "allow_cloud_llm": allow_cloud_llm,
        "cloud_provider_allowlist": list(cloud_provider_allowlist),
    }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


@pytest.fixture(autouse=True)
def _reset_enforce_state() -> Any:
    enforce._reset_state()
    yield
    enforce._reset_state()


# --------------------------------------------------------------------------- #
# POLICY.md row 7 — policy.strict.cloud_allowlisted (allow + cloud)           #
# --------------------------------------------------------------------------- #


class TestCloudAllowlistedReason:
    def test_allow_entry_shape(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            health_probe=_noop_probe,
        )

        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry["event"] == "on_session_start"
        assert entry["decision"] == "allow"
        assert entry["reason"] == "policy.strict.cloud_allowlisted"
        assert entry["provider_id"] == "anthropic"


# --------------------------------------------------------------------------- #
# POLICY.md row 7 — same reason used for the local passthrough audit          #
# --------------------------------------------------------------------------- #


class TestLocalPassthroughAuditReason:
    def test_local_provider_emits_cloud_allowlisted_reason(self, tmp_path: Path) -> None:
        """``mordred-local`` doesn't have its own reason code in the
        frozen enum; reuse ``policy.strict.cloud_allowlisted`` (decision=allow)
        because the operational outcome is identical: an allow under strict.
        """
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_noop_probe,
        )

        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry["decision"] == "allow"
        assert entry["reason"] == "policy.strict.cloud_allowlisted"
        assert entry["provider_id"] == "mordred-local"


# --------------------------------------------------------------------------- #
# POLICY.md rows 8 + 10 — classification + action on refused cloud            #
# --------------------------------------------------------------------------- #


class TestCloudRefusedReasons:
    def test_classification_before_action(self, tmp_path: Path) -> None:
        """Codex N1 (POLICY.md row 8 note): the classification reason
        ``policy.strict.cloud_not_allowlisted`` is recorded **before**
        the action ``policy.strict.session_refused`` so a chronological
        replay sees classification → action → raise.
        """
        cfg = _write_policy_json(
            tmp_path,
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="bedrock",
                audit=audit,
                health_probe=_noop_probe,
            )

        assert len(audit.entries) == 2
        first, second = audit.entries
        assert first["reason"] == "policy.strict.cloud_not_allowlisted"
        assert first["decision"] == "block"
        assert first["provider_id"] == "bedrock"
        assert first["allow_cloud_llm"] is True

        assert second["reason"] == "policy.strict.session_refused"
        assert second["decision"] == "block"
        assert second["provider_id"] == "bedrock"

    def test_allow_cloud_llm_false_records_classification_with_flag(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            allow_cloud_llm=False,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

        first = audit.entries[0]
        assert first["reason"] == "policy.strict.cloud_not_allowlisted"
        assert first["allow_cloud_llm"] is False


# --------------------------------------------------------------------------- #
# POLICY.md rows 6 + 9 — degraded path                                        #
# --------------------------------------------------------------------------- #


class TestDegradedReasons:
    def test_no_resolved_provider_then_unconditional_override(self, tmp_path: Path) -> None:
        """Order:

        1. ``mordred.degraded.no_resolved_provider`` (one-shot, row 6)
        2. ``policy.strict.unconditional_override`` (action, row 9)

        Both decisions are ``block`` in v1 (refuse-only).
        """
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )

        assert len(audit.entries) == 2
        first, second = audit.entries
        assert first["reason"] == "mordred.degraded.no_resolved_provider"
        assert first["decision"] == "block"
        assert second["reason"] == "policy.strict.unconditional_override"
        assert second["decision"] == "block"

    def test_one_shot_skips_no_resolved_provider_on_second_call(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )
        audit.entries.clear()
        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )
        reasons = [e["reason"] for e in audit.entries]
        assert "mordred.degraded.no_resolved_provider" not in reasons
        assert "policy.strict.unconditional_override" in reasons


# --------------------------------------------------------------------------- #
# Frozen enum membership — POLICY.md must agree with emitted reasons          #
# --------------------------------------------------------------------------- #


class TestFrozenEnumMembership:
    _FROZEN_REASONS = frozenset(
        {
            "policy.strict.cloud_allowlisted",
            "policy.strict.cloud_not_allowlisted",
            "policy.strict.cloud_prompted_allow",
            "policy.strict.cloud_prompted_deny",
            "policy.strict.session_refused",
            "policy.strict.unconditional_override",
            "mordred.degraded.no_resolved_provider",
        }
    )

    def test_all_emitted_reasons_are_in_freeze(self, tmp_path: Path) -> None:
        audit = _FakeAuditWriter()

        # Allow allowlisted cloud
        a = tmp_path / "a"
        a.mkdir()
        cfg = _write_policy_json(
            a,
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            health_probe=_noop_probe,
        )

        # Allow local
        b = tmp_path / "b"
        b.mkdir()
        cfg = _write_policy_json(b)
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_noop_probe,
        )

        # Cloud refused
        c = tmp_path / "c"
        c.mkdir()
        cfg = _write_policy_json(c)
        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="bedrock",
                audit=audit,
                health_probe=_noop_probe,
            )

        # Degraded
        d = tmp_path / "d"
        d.mkdir()
        cfg = _write_policy_json(d)
        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )

        emitted = {e["reason"] for e in audit.entries}
        unknown = emitted - self._FROZEN_REASONS
        assert not unknown, f"unfrozen reasons emitted: {sorted(unknown)}"


# --------------------------------------------------------------------------- #
# prompt-once reasons must be members of the frozen ReasonCode Literal         #
# --------------------------------------------------------------------------- #


class TestPromptedReasonsFrozen:
    def test_prompted_reasons_are_in_reasoncode_literal(self) -> None:
        """The two prompt-once decision reasons emitted by
        :func:`enforce._resolve_cloud_attempt` must be frozen in
        ``_audit_reasons.ReasonCode`` (POLICY.md scope rule: codes with a
        same-PR emit site).
        """
        from typing import get_args

        from mordred_hermes.privacy_check import _audit_reasons

        frozen = set(get_args(_audit_reasons.ReasonCode))
        assert "policy.strict.cloud_prompted_allow" in frozen
        assert "policy.strict.cloud_prompted_deny" in frozen
        assert "policy.strict.cloud_endpoint_mismatch" in frozen
