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

Phase 4 codes (``keyvault.*``) are intentionally NOT included — Phase 4's
step-0 freeze adds its own codes alongside the SPEC.md update.
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
]
