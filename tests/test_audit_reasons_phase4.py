"""Phase 4 PR2 + PR3 step-0 freeze of ``keyvault.*`` audit reason codes.

Per ``docs/dev/POLICY.md`` §Phase 4 step-0 freeze (added
2026-05-14, PR2 + PR3): only codes with an emit site OR already
referenced by frozen SPEC text are included.

PR2 adds 2 codes (already landed):

- ``keyvault.recovery_digest_mismatch`` — emitted by
  ``recovery.import_backup`` BEFORE AES-GCM decryption runs, paired with
  :class:`mordred_hermes.keyvault.recovery.RecoveryDigestMismatch` raise.
  Codex review #4: verify-before-decrypt prevents secret materialization
  on mismatch. Decision ``block``. Fields: ``blob_version``,
  ``event="keyvault.import_backup"``.
- ``keyvault.seed_display_aborted_screenshot`` — SPEC §Seed phrase display
  security requires this stable reason at the ``seed_display.py`` emit site.
  Decision
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

PR4 step-D (``keyvault.init_*``) and step-E (``keyvault.backup_exported``)
reason codes graduate into the freeze as each emit site lands — the
"freeze a code only once it has an emit site" discipline that avoids the
"frozen but unused" footgun Phase 2 hit with
``policy.strict.local_stream_interrupted`` (POLICY.md entry #12).
``keyvault.backup_exported`` (#24) is frozen as of step-E because
``api.export_backup`` now emits it; the membership assertion lives in
``test_keyvault_api_backup.test_backup_exported_is_now_in_freeze``
alongside the emit-site behavior tests.
"""

from __future__ import annotations

from typing import get_args


def test_keyvault_codes_use_dotted_form() -> None:
    """Naming convention check: ``keyvault.*`` mirrors ``policy.*`` /
    ``mordred.*`` / ``network.*`` dotted form."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    keyvault_codes = [c for c in get_args(ReasonCode) if c.startswith("keyvault")]
    assert keyvault_codes, "Phase 4 freeze added no keyvault.* codes"
    for code in keyvault_codes:
        assert "." in code, f"underscore-form {code!r} violates dotted convention"
        assert "_" not in code.split(".", 1)[0], (
            f"prefix segment of {code!r} must be a single token (got {code.split('.', 1)[0]!r})"
        )


def test_keyvault_audit_reason_contract() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    expected = {
        "keyvault.recovery_digest_mismatch",
        "keyvault.unwrap_denied",
        "keyvault.init_completed",
        "policy.strict.keyvault_uninitialized",
        "keyvault.unwrap_authorized",
        "keyvault.init_denied",
        "policy.lenient.keyvault_uninitialized_warning",
        "keyvault.seed_display_aborted_screenshot",
        "keyvault.init_started",
    }
    assert expected <= set(get_args(ReasonCode))
