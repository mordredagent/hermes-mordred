"""Frozen audit-log reason enum.

The set is closed at the type level via ``Literal`` so any drift between
``audit.append(reason=...)`` and the freeze list surfaces as a mypy error.

Phase 1 step 0 freeze (per TODO §1 open decision, 2026-05-10):

- 9 codes from SPEC.md §Audit log policy (L417-426)
- 1 from M2 (mid-stream local-endpoint death, ``policy.strict.local_stream_interrupted``)
- 2 already documented in SPEC.md §Story 4 / §Plugin: ``mordred_llm_guard``
  (``policy.strict.session_refused``, ``policy.strict.provider_override_at_session_start``)

Phase 3 PR1 step-0 freeze (2026-05-13) adds 4 ``network.*`` codes:

- ``network.use`` — successful path switch via ``api.use(path)``
  (decision=``override``, fields ``prev_path`` / ``new_path`` /
  ``live_subprocess_count`` for M3 transitive-failure visibility)
- ``network.use_failed`` — ``api.use(path)`` raised :class:`MordredNetworkError`
  (decision=``raise``)
- ``network.bringup_failed`` — lenient-mode bring-up failure with clearnet
  fallback; strict mode pairs this with a :class:`MordredPathBringupFailed`
  raise
- ``network.path_dropped`` — M9 liveness probe detected 2 consecutive
  failures (decision=``block`` in strict, ``warn`` in lenient)

Naming normalized to dotted form (``network.use`` rather than ``network_use``
as in TODO.md L331) to match the existing ``policy.*`` / ``mordred.*``
convention. Documented in POLICY.md.

Phase 4 PR2 step-0 freeze (2026-05-14) adds 2 ``keyvault.*`` codes,
scoped narrowly per Codex review #8 — only codes with a PR2 emit site
OR already referenced by frozen SPEC text are included now:

- ``keyvault.recovery_digest_mismatch`` — emitted by ``recovery.import_backup``
  before AES-GCM decryption runs, paired with
  :class:`mordred_hermes.keyvault.recovery.RecoveryDigestMismatch` raise.
  Codex review #4: verify-before-decrypt prevents secret materialization
  on mismatch.
- ``keyvault.seed_display_aborted_screenshot`` — SPEC §Seed phrase display
  security L352 already references this; PR2 freezes it so the PR4
  ``seed_display.py`` emit site has a stable target.

Phase 4 PR3 step-0 freeze (2026-05-14) adds 2 ``keyvault.*`` codes for
Secure-Enclave-authorized DEK unwrap. The codex review on the PR3 plan
(BLOCKER-1 / HIGH-3) corrected the authorization boundary: wrap uses
the Enclave **public** key + a software ephemeral private and never
prompts the user, so only unwrap can emit authorization-decision
audit entries:

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

PR4 codes (``keyvault.init_started`` / ``keyvault.init_completed`` /
``keyvault.backup_exported``) are deliberately NOT frozen here — they
land in their respective step-0 freezes once the emit site exists, to
avoid the "frozen but unused" footgun that Phase 2 hit with
``policy.strict.local_stream_interrupted`` (POLICY.md entry #12 caveat).
"""

from typing import Literal

ReasonCode = Literal[
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
    "network.use",
    "network.use_failed",
    "network.bringup_failed",
    "network.path_dropped",
    "keyvault.recovery_digest_mismatch",
    "keyvault.seed_display_aborted_screenshot",
    "keyvault.unwrap_authorized",
    "keyvault.unwrap_denied",
]
