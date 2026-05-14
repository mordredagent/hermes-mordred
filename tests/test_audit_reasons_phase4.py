"""Phase 4 PR2 + PR3 step-0 freeze of ``keyvault.*`` audit reason codes.

Per ``mordred-docs/mordred/POLICY.md`` §Phase 4 step-0 freeze (added
2026-05-14, PR2 + PR3): only codes with an emit site OR already
referenced by frozen SPEC text are included.

PR2 adds 2 codes (already landed):

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

PR3 adds 2 codes (this PR) for Secure-Enclave-authorized DEK unwrap.
Authorization happens on **unwrap** only — wrap uses the Enclave public
key + a software ephemeral private key and never prompts the user
(codex review BLOCKER-1 / HIGH-3):

- ``keyvault.unwrap_authorized`` — emitted by ``wrap.unwrap_dek`` after
  ``SecKeyCopyKeyExchangeResult`` succeeds (biometric / passcode access
  control satisfied). Decision ``allow``. Fields:
  ``event="keyvault.unwrap_dek"``, ``key_id_hash`` (hex prefix; never
  the full ``key_id``).
- ``keyvault.unwrap_denied`` — emitted when the Enclave returns
  ``errSecUserCancelled`` / ``errSecAuthFailed`` / equivalent NSError,
  paired with :class:`mordred_hermes.keyvault.wrap.WrapAuthCancelled`
  raise. Decision ``block``. Fields: ``event="keyvault.unwrap_dek"``,
  ``native_error_code`` (translated; never the raw OSStatus).

PR4 (``keyvault.init_*`` / ``keyvault.backup_exported``) reason codes
are deliberately NOT in the freeze yet — they land in PR4 step-0 once
the emit site exists, to avoid the "frozen but unused" footgun that
Phase 2 hit with ``policy.strict.local_stream_interrupted`` (POLICY.md
entry #12).
"""

from __future__ import annotations

from typing import get_args


def test_keyvault_recovery_digest_mismatch_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.recovery_digest_mismatch" in get_args(ReasonCode)


def test_keyvault_seed_display_aborted_screenshot_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.seed_display_aborted_screenshot" in get_args(ReasonCode)


def test_keyvault_unwrap_authorized_in_freeze() -> None:
    """PR3 step-0 freeze: emit site is ``wrap.unwrap_dek`` after a
    successful ``SecKeyCopyKeyExchangeResult`` call. Codex review
    BLOCKER-1: authorization happens on unwrap, not wrap."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.unwrap_authorized" in get_args(ReasonCode)


def test_keyvault_unwrap_denied_in_freeze() -> None:
    """PR3 step-0 freeze: paired with
    :class:`mordred_hermes.keyvault.wrap.WrapAuthCancelled` raise when the
    Enclave returns ``errSecUserCancelled`` / ``errSecAuthFailed``."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.unwrap_denied" in get_args(ReasonCode)


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
