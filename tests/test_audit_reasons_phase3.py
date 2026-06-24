"""Phase 3 step-0 freeze of ``network.*`` audit reason codes.

Per ``mordred-docs/mordred/TODO.md`` L13:

    "Phase 3/4 codes (``network.*``, ``keyvault.*``) are intentionally NOT
    included [in the Phase 1 12-code freeze] — each phase's step-0 freeze
    adds its own codes alongside the SPEC.md update."

Phase 3 PR1 adds 4 codes to the central ``privacy_check._audit_reasons.ReasonCode``
``Literal`` (single source of truth, referenced from every plugin's audit
emit site):

- ``network.use`` — successful path switch via ``api.use(path)``. Decision
  ``override``. Fields: ``prev_path`` / ``new_path`` / ``live_subprocess_count``
  (M3 transitive-failure visibility — ``> 0`` means env updates won't reach
  already-running children).
- ``network.use_failed`` — ``api.use(path)`` raised :class:`MordredNetworkError`.
  Decision ``raise``. Fields: ``requested_path`` / ``error_type`` / ``prev_path``.
- ``network.bringup_failed`` — lenient-mode path bring-up failure with
  clearnet fallback. Decision ``warn``. Fields: ``path`` / ``error_type``.
  Strict mode emits this *and* raises :class:`MordredPathBringupFailed`.
- ``network.path_dropped`` — M9 liveness probe detected 2 consecutive
  failures. Decision ``block`` (strict) / ``warn`` (lenient). Fields:
  ``path`` / ``consecutive_failures`` / ``last_health_at``.

Naming normalized to dotted form (``network.use`` rather than ``network_use``
as in TODO.md L331) to match the existing ``policy.*`` / ``mordred.*``
convention. The deviation is documented in POLICY.md.

Total freeze after PR1: 12 (Phase 1) + 4 (Phase 3) = 16 codes.
"""

from __future__ import annotations

from typing import get_args


def test_network_use_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.use" in get_args(ReasonCode)


def test_network_use_failed_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.use_failed" in get_args(ReasonCode)


def test_network_bringup_failed_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.bringup_failed" in get_args(ReasonCode)


def test_network_path_dropped_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.path_dropped" in get_args(ReasonCode)


def test_phase1_freeze_preserved() -> None:
    """Adding Phase 3 codes must not remove or rename Phase 1 codes."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    phase1_codes = {
        "policy.strict.clearnet",
        "policy.strict.unknown_metadata",
        "policy.strict.unconditional_override",
        "policy.strict.cloud_not_allowlisted",
        "policy.strict.cloud_allowlisted",
        "policy.lenient.unknown_metadata_warning",
        "mordred.degraded.disable_unprotected",
        "mordred.degraded.no_origin_skill",
        "mordred.degraded.no_resolved_provider",
        "policy.strict.local_stream_interrupted",
        "policy.strict.session_refused",
        "policy.strict.provider_override_at_session_start",
    }
    members = set(get_args(ReasonCode))
    missing = phase1_codes - members
    assert not missing, f"Phase 1 codes accidentally removed: {sorted(missing)}"


def test_total_freeze_size_after_prompt_once() -> None:
    """After the prompt-once freeze: 12 Phase 1 + 4 Phase 3 +
    2 Phase 4 PR2 + 2 Phase 4 PR3 + 3 Phase 4 PR4c (keyvault.init_*) +
    1 Phase 4 PR4 step-E (keyvault.backup_exported) + 2 Phase 4 §4.1
    (policy.*.keyvault_uninitialized) + 1 PR #39 review follow-up
    (mordred.degraded.audit_encryption_unavailable) + 2 prompt-once
    (policy.strict.cloud_prompted_allow / _deny) = 29.

    The §4.1 codes graduated into the freeze because their emit site —
    ``install_wrapper.run``'s ``requires_keyvault`` enforcement — exists.
    The PR #39 follow-up code has its emit site in
    ``audit.make_audit_writer``'s encrypted→plaintext fallback branch. The
    prompt-once codes have their emit site in
    ``llm_guard.enforce._resolve_cloud_attempt``.

    If a future PR bumps this, update POLICY.md's "Total freeze becomes N"
    statement in the same commit so the doc and the type stay in lockstep.
    """
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert len(get_args(ReasonCode)) == 29


def test_no_underscore_typo_legacy_name() -> None:
    """Catch the TODO.md L331 ``network_use`` form (deviates from dotted
    convention). PR1 normalized to ``network.use``."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    members = set(get_args(ReasonCode))
    assert "network_use" not in members
    assert "network.use" in members
