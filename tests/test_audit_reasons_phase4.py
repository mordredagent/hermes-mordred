"""Phase 4 PR2 step-0 freeze of ``keyvault.*`` audit reason codes.

Per ``mordred-docs/mordred/POLICY.md`` §Phase 4 step-0 freeze (added
2026-05-14, PR2): only codes with a PR2 emit site OR already referenced
by frozen SPEC text are included now.

PR2 adds 2 codes:

- ``keyvault.recovery_digest_mismatch`` — emitted by
  ``recovery.import_backup`` BEFORE AES-GCM decryption runs, paired with
  :class:`mordred_hermes.keyvault.recovery.RecoveryDigestMismatch` raise.
  Codex review #4: verify-before-decrypt prevents secret materialization
  on mismatch. Decision ``block``. Fields: ``blob_version``,
  ``event="keyvault.import_backup"``.
- ``keyvault.seed_display_aborted_screenshot`` — SPEC §Seed phrase
  display security L352 already references this; PR2 freezes it so the
  PR4 ``seed_display.py`` emit site has a stable target. Decision
  ``block``. Fields: ``event="keyvault.seed_display"``, ``detector``.

PR3 (``keyvault.unwrap_*``) and PR4 (``keyvault.init_*`` /
``keyvault.backup_exported``) reason codes are deliberately NOT in the
freeze yet — they land in their respective step-0 freezes once the emit
site exists, to avoid the "frozen but unused" footgun that Phase 2 hit
with ``policy.strict.local_stream_interrupted`` (POLICY.md entry #12).
"""

from __future__ import annotations

from typing import get_args


def test_keyvault_recovery_digest_mismatch_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.recovery_digest_mismatch" in get_args(ReasonCode)


def test_keyvault_seed_display_aborted_screenshot_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.seed_display_aborted_screenshot" in get_args(ReasonCode)


def test_phase4_unwrap_codes_deliberately_not_frozen_yet() -> None:
    """Codex review #8: PR3 codes have no emit site in PR2, so freezing
    them now would create the same "frozen but unused" footgun as Phase 2
    ``policy.strict.local_stream_interrupted``. Re-add when PR3 lands."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    members = set(get_args(ReasonCode))
    assert "keyvault.unwrap_authorized" not in members
    assert "keyvault.unwrap_denied" not in members


def test_phase4_init_codes_deliberately_not_frozen_yet() -> None:
    """Codex review #8: PR4 ``api.generate`` / ``audit purge`` codes are
    not in freeze yet — they land alongside ``api.py`` (Phase 4 PR4)."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    members = set(get_args(ReasonCode))
    assert "keyvault.init_started" not in members
    assert "keyvault.init_completed" not in members
    assert "keyvault.backup_exported" not in members


def test_keyvault_codes_use_dotted_form() -> None:
    """Naming convention check: ``keyvault.*`` mirrors ``policy.*`` /
    ``mordred.*`` / ``network.*`` dotted form (POLICY.md L43 note)."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    keyvault_codes = [c for c in get_args(ReasonCode) if c.startswith("keyvault")]
    assert keyvault_codes, "Phase 4 freeze added no keyvault.* codes"
    for code in keyvault_codes:
        assert "." in code, f"underscore-form {code!r} violates dotted convention"
        assert "_" not in code.split(".", 1)[0], (
            f"prefix segment of {code!r} must be a single token (got {code.split('.', 1)[0]!r})"
        )
