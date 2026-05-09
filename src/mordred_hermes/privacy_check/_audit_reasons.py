"""Frozen audit-log reason enum.

The set is closed at the type level via ``Literal`` so any drift between
``audit.append(reason=...)`` and the freeze list surfaces as a mypy error.

Phase 1 step 0 freeze (per TODO §1 open decision, 2026-05-10):

- 9 codes from SPEC.md §Audit log policy (L417-426)
- 1 from M2 (mid-stream local-endpoint death, ``policy.strict.local_stream_interrupted``)
- 2 already documented in SPEC.md §Story 4 / §Plugin: ``mordred_llm_guard``
  (``policy.strict.session_refused``, ``policy.strict.provider_override_at_session_start``)

Phase 3/4 codes (``network.*``, ``keyvault.*``) are intentionally NOT included —
each phase's step-0 freeze adds its own codes alongside the SPEC.md update.
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
]
