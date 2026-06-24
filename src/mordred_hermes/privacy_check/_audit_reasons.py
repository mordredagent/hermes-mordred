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

Phase 4 PR4 step-D (PR4c-2, 2026-05-15) adds 3 ``keyvault.init_*`` codes
for the two-phase key-generation lifecycle. Each has a same-PR emit site
in ``api.confirm_generate`` (POLICY.md #21-23):

- ``keyvault.init_started`` — durability barrier, emitted before any
  Keychain / meta.json mutation. Decision ``allow``. Fields:
  ``event="keyvault.init"``, ``key_id_hash``. If the audit sink raises
  during this emit the whole init aborts (fail-closed) — failing open
  would diverge audit from observable state.
- ``keyvault.init_completed`` — success path: Enclave key created,
  meta.json row + ``digests/<kid>.commit`` persisted. Decision ``allow``.
  Fields: ``event="keyvault.init"``, ``key_id_hash``,
  ``verification_digest_hex_prefix``. Sink failure suppressed (init is
  already durable).
- ``keyvault.init_denied`` — digest mismatch, paired with a
  :class:`VerificationDigestMismatch` raise, emitted before any mutation.
  Decision ``block``. Fields: ``event="keyvault.init"``, ``key_id_hash``.
  Sink failure is chained as ``__context__`` on the raised exception.

Phase 4 PR4 step-E (2026-05-16) adds 1 ``keyvault.backup_exported`` code.
Its emit site — ``api.export_backup`` — landed in step-E, so the code
graduates into the freeze under condition (a) ("has a same-PR emit
site"), bringing the total to 24:

- ``keyvault.backup_exported`` — emitted by ``api.export_backup`` once the
  portable MRKV backup blob is materialized. Decision ``allow``. Fields:
  ``event="keyvault.backup_export"``, ``key_id_hash``, ``blob_version=1``,
  ``kdf_id=1``, ``envelope_count``. Success-path emit — a sink failure is
  suppressed via ``contextlib.suppress`` (the blob is already returned).

Phase 4 §4.1 freeze (2026-05-16) adds 2 install-time ``policy.*`` codes
for ``metadata.mordred.requires_keyvault`` opt-in enforcement. Both have a
same-PR emit site in ``install_wrapper.run`` (``pre_install`` event),
bringing the total to 26:

- ``policy.strict.keyvault_uninitialized`` — strict policy; the skill
  declares ``requires_keyvault: true`` but the Mordred keyvault holds no
  keys. Decision ``block`` (paired with an :class:`InstallBlocked` raise).
  The keyvault-initialized check is backend-free (``meta.json`` read only,
  see :mod:`._keyvault_probe`) so the decision is reproducible on every
  platform.
- ``policy.lenient.keyvault_uninitialized_warning`` — lenient policy; same
  precondition. Decision ``warn`` — install proceeds, the operator is
  informed via the audit log (mirrors ``policy.lenient.unknown_metadata_warning``).

Phase 4 PR #39 review follow-up (2026-05-17) adds 1 ``mordred.degraded.*``
code, bringing the total to 27:

- ``mordred.degraded.audit_encryption_unavailable`` — emitted by
  ``audit.make_audit_writer`` when the keyvault is initialized (or its
  state could not be read) but the encrypted :class:`EncryptedWriter`
  cannot be built, so privacy_check falls open to a plaintext
  :class:`NDJSONWriter`. Decision ``warn``. Fields:
  ``event="mordred.audit_writer"``, ``detail`` (the fallback-triggering
  exception's type + message; never key material). The clean
  "keyvault never initialized" path stays silent — that is the baseline,
  not a downgrade.

prompt-once step-0 freeze (2026-06-24) adds 2 ``policy.strict.cloud_prompted_*``
codes, bringing the total to 29. Both have a same-PR emit site in
:func:`mordred_hermes.llm_guard.enforce._resolve_cloud_attempt` (POLICY.md
scope rule condition (a)):

- ``policy.strict.cloud_prompted_allow`` — ``cloud_attempt_action: prompt-once``
  and the operator approved a one-time call to a non-allowlisted cloud
  provider at an interactive terminal. Decision ``allow``. Fields:
  ``event="pre_api_request"``, ``provider_id``. Emitted once per provider
  (the verdict is cached for the process), so cached re-allows stay silent.
- ``policy.strict.cloud_prompted_deny`` — same precondition, but the operator
  declined OR no interactive terminal was available (fail-closed). Decision
  ``block``, paired with the existing ``cloud_not_allowlisted`` +
  ``session_refused`` action pair. Fields: ``event="pre_api_request"``,
  ``provider_id``, and ``prompt_unavailable: true`` when the deny was the
  no-terminal fallback rather than an explicit decline.
"""

from typing import Literal

ReasonCode = Literal[
    "policy.strict.clearnet",
    "policy.strict.unknown_metadata",
    "policy.strict.unconditional_override",
    "policy.strict.cloud_not_allowlisted",
    "policy.strict.cloud_allowlisted",
    "policy.strict.cloud_prompted_allow",
    "policy.strict.cloud_prompted_deny",
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
    "keyvault.init_started",
    "keyvault.init_completed",
    "keyvault.init_denied",
    "keyvault.backup_exported",
    "policy.strict.keyvault_uninitialized",
    "policy.lenient.keyvault_uninitialized_warning",
    "mordred.degraded.audit_encryption_unavailable",
]
