"""Closed audit-log reason vocabulary.

``ReasonCode`` is deliberately a ``Literal`` so mypy catches drift between
emit sites and consumers. ``docs/dev/POLICY.md`` owns the current meaning and
live/reserved status of every value. Existing strings are compatibility
surfaces: add or retire behavior without renaming an established code.

Two values are reserved and have no current emit site:

- ``policy.strict.local_stream_interrupted`` — no reliable plugin-side
  streaming-interruption seam exists.
- ``policy.strict.provider_override_at_session_start`` — current strict LLM
  behavior refuses; it does not replace the provider.

``policy.strict.unconditional_override`` is also a legacy name, but it remains
live for an unresolved-provider refusal. Its name must not be read as evidence
that an override occurred.

``EgressRule`` is the closed vocabulary of the ``rule`` field that tool-egress
audit entries carry next to their ``reason`` (``policy.egress.tool_blocked``
for a refusal or an approval prompt). The ``egress.reader_*`` rules belong to
reader mode: a session that has read imported private history may no longer
act on it (see :mod:`.egress`).
"""

from typing import Literal

ReasonCode = Literal[
    "policy.strict.clearnet",
    "policy.strict.unknown_metadata",
    "policy.strict.unconditional_override",
    "policy.strict.cloud_not_allowlisted",
    "policy.strict.cloud_allowlisted",
    "policy.strict.cloud_endpoint_mismatch",
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
    "network.transport_incompatible",
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
    "policy.egress.tool_blocked",
    "mordred.db_encryption.violation",
    "activity.capture_refused",
    "policy.egress.reader_mode",
]

EgressRule = Literal[
    "egress.ask",
    "egress.blocked_tool",
    "egress.blocklisted_domain",
    "egress.delegate_tainted",
    "egress.evaluation_failed",
    "egress.lockdown",
    "egress.malformed_bridge",
    "egress.outbound_tool",
    "egress.schedule",
    "egress.tainted_persist",
    "egress.tainted_session",
    "egress.uninspectable_exec",
    "egress.url_fetch",
    "egress.reader_no_session",
    "egress.reader_unrecorded",
    "egress.reader_locked",
    "egress.reader_web",
]
