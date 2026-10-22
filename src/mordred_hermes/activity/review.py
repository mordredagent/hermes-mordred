"""Conditional, tool-free review of browser-activity episodes (phase 3).

Programs own eligibility, scheduling, budgets and adoption; the model only
assesses one bounded snapshot and answers with JSON that Mordred validates
itself (the host may skip schema validation when ``jsonschema`` is absent).

- **Eligibility** (:func:`eligible_episodes`) is plain code over durable
  episodes: an unreviewed revision plus a meaningful signal (an explicit
  correction, a verified failure followed by a success of the same step, or
  a procedure completed in at least three distinct episodes). Elapsed time
  or event count alone never qualifies.
- **Jobs** (``activity_review_jobs``) move ``pending → leased → calling →
  completed | deferred | failed | uncertain``; one job per
  ``(episode_id, input_revision, REVIEWER_VERSION)``. The snapshot digest is
  frozen at enqueue time; a moved revision or changed snapshot defers the job.
- **Budget** (``activity_review_attempts`` / ``activity_budget``): every
  physical provider attempt is reserved and persisted before submission. A
  request that may have reached the provider becomes ``uncertain`` and is
  never resubmitted automatically; an explicit retry records a new attempt.
- **Routing** is explicit: the host's ``task=`` argument when the facade has
  it, else a configured provider/model override, else no review.

The worker is a plain function; callers choose the thread. This module is
the facade; the bodies live in ``_review_output`` (instructions, schema,
validator), ``_review_snapshot`` (snapshot, eligibility), ``_review_jobs``
(jobs, leases, attempts, budget, audit) and ``_review_run`` (routing, the run). Logs and audit
entries carry identifiers, codes and token counts only — never snapshot,
lesson or model text.
"""

from __future__ import annotations

from ._review_jobs import (
    LEASE_TTL_S,
    AuditSink,
    ReconcileReport,
    default_audit_sink,
    enqueue,
    get_job,
    is_local_route,
    lease,
    list_jobs,
    oldest_pending,
    reclaim_stale,
    reconcile_store,
    reopen_for_retry,
    reserve_attempt,
)
from ._review_output import (
    OUTPUT_SCHEMA,
    REVIEW_INSTRUCTIONS,
    REVIEW_TASK,
    REVIEWER_VERSION,
    OutputRejected,
    ReviewOutput,
    validate_output,
)
from ._review_run import (
    ReviewOutcome,
    Route,
    open_review_store,
    resolve_llm,
    resolve_route,
    run_one_pending,
    run_review,
)
from ._review_snapshot import build_snapshot, eligible_episodes

__all__ = [
    "LEASE_TTL_S",
    "OUTPUT_SCHEMA",
    "REVIEWER_VERSION",
    "REVIEW_INSTRUCTIONS",
    "REVIEW_TASK",
    "AuditSink",
    "OutputRejected",
    "ReconcileReport",
    "ReviewOutcome",
    "ReviewOutput",
    "Route",
    "build_snapshot",
    "default_audit_sink",
    "eligible_episodes",
    "enqueue",
    "get_job",
    "is_local_route",
    "lease",
    "list_jobs",
    "oldest_pending",
    "open_review_store",
    "reclaim_stale",
    "reconcile_store",
    "reopen_for_retry",
    "reserve_attempt",
    "resolve_llm",
    "resolve_route",
    "run_one_pending",
    "run_review",
    "validate_output",
]
