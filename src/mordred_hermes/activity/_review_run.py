"""Routing and the review run: lease, freeze, route, reserve, submit once, validate, commit."""

from __future__ import annotations

import contextlib
import importlib
import inspect
import json
import logging
import math
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from . import _review_jobs
from ._gate import ActivityRefused, Refusal, refusal
from ._review_jobs import (
    LEASE_TTL_S,
    AuditSink,
    JobRow,
    Usage,
    audit_attempt,
    bounded_name,
    get_job,
    lease,
    oldest_pending,
    reclaim_stale,
    reserve_attempt,
    set_attempt_state,
    set_job_state,
)
from ._review_output import (
    LESSON_KEYS,
    OUTPUT_SCHEMA,
    REVIEW_INSTRUCTIONS,
    REVIEW_TASK,
    OutputRejected,
    ReviewOutput,
    validate_output,
)
from ._review_snapshot import Snapshot, build_snapshot, transaction
from .config import ActivityConfig

if TYPE_CHECKING:
    from .store import ActivityStore

_LOG = logging.getLogger("mordred.activity.review")

_TASK_LIMIT: Final = 300
#: Store faults propagate to the caller; any other refusal while saving a candidate fails the job.
_STORE_FAULTS: Final = frozenset({"busy", "disk_full", "store_unavailable"})


def open_review_store(home: Path) -> ActivityStore:
    """The gated store of ``home`` (raises :class:`._gate.ActivityRefused`)."""
    from ._gate import open_store

    return open_store(home)


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Route:
    #: task | override
    kind: str
    task: str | None = None
    provider: str | None = None
    model: str | None = None

    def call_kwargs(self) -> dict[str, Any]:
        if self.kind == "task":
            return {"task": self.task}
        return {"provider": self.provider, "model": self.model}


def _policy_mode() -> str:
    with contextlib.suppress(Exception):
        from ..privacy_check import _runtime

        return str(_runtime.ensure_state().policy_mode)
    return "strict"  # fail closed if the policy cannot be read


def _guard_installed() -> bool:
    try:
        from ..llm_guard import auxiliary_guard
    except ImportError:
        return False
    return bool(auxiliary_guard._installed)


def resolve_route(llm: Any, config: ActivityConfig) -> Route | Refusal:
    """The host's own task routing when available, else an explicit override, else no review."""
    if _policy_mode() == "strict" and not _guard_installed():
        return refusal("guard_unavailable")
    method = getattr(llm, "complete_structured", None)
    if method is None:
        return refusal("route_unavailable")
    try:
        parameters = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return refusal("route_unavailable")
    if "task" in parameters:
        return Route("task", task=REVIEW_TASK)
    if config.review_provider and config.review_model:
        return Route("override", provider=config.review_provider, model=config.review_model)
    return refusal("route_unavailable")


def resolve_llm() -> Any:
    """The host LLM lane for the CLI (``PluginLlm(plugin_id="mordred")``), or a ``route_unavailable`` refusal."""
    try:
        module = importlib.import_module("agent.plugin_llm")
    except ImportError:
        return refusal("route_unavailable")
    return module.PluginLlm(plugin_id="mordred")


# --------------------------------------------------------------------------- #
# The review run
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ReviewOutcome:
    job_id: str
    #: the job state after the run (``pending`` when admission was refused)
    state: str
    failure_code: str | None
    lesson_id: str | None
    revision: int
    usage: Usage = field(default_factory=Usage)
    provider_called: bool = False


@dataclass(frozen=True)
class _Run:
    store: ActivityStore
    job: JobRow
    config: ActivityConfig
    now: float
    sink: AuditSink

    def outcome(self, state: str, code: str | None, **extra: Any) -> ReviewOutcome:
        lesson_id = extra.pop("lesson_id", None)
        return ReviewOutcome(self.job.job_id, state, code, lesson_id, self.job.input_revision, **extra)

    def finish_job(self, state: str, code: str | None) -> ReviewOutcome:
        with transaction(self.store) as conn:
            set_job_state(conn, self.job.job_id, state, code, self.now)
        return self.outcome(state, code)


def _frozen_snapshot(run: _Run, excluded_sites: frozenset[str]) -> Snapshot | str:
    """The job's frozen input, or the code that defers it (moved revision, changed or missing evidence)."""
    episode = run.store.episode(run.job.episode_id)
    if episode is None or episode.revision > run.job.input_revision:
        return "evidence_changed"
    snapshot = build_snapshot(
        run.store,
        run.job.episode_id,
        run.job.input_revision,
        max_input_tokens=run.config.review_max_input_tokens,
        excluded_sites=excluded_sites,
    )
    return snapshot if snapshot.digest == run.job.snapshot_digest else "snapshot_changed"


def _mark_submitted(run: _Run, attempt_id: str) -> None:
    hold = max(LEASE_TTL_S, run.config.review_timeout_s * 4.0)
    with transaction(run.store) as conn:
        conn.execute(
            "UPDATE activity_review_jobs SET state = 'calling', lease_expires_at = ?, updated_at = ? WHERE job_id = ?",
            (run.now + hold, run.now, run.job.job_id),
        )
        conn.execute("UPDATE activity_review_attempts SET state = 'submitted' WHERE attempt_id = ?", (attempt_id,))
    audit_attempt(run.sink, run.job.job_id, attempt_id, "submitted")


def _is_timeout(exc: BaseException) -> bool:
    return "Timeout" in type(exc).__name__ or "timed out" in str(exc).lower()


def _call_failed(run: _Run, attempt_id: str, exc: BaseException) -> ReviewOutcome:
    # Type names only: provider messages may echo request content.
    _LOG.warning("activity review call failed (%s, job=%s)", type(exc).__name__, run.job.job_id)
    if _is_timeout(exc):
        attempt_state, job_state, code = "uncertain", "uncertain", "timeout"
    elif isinstance(exc, PermissionError):
        attempt_state, job_state, code = "failed", "failed", "route_refused"
    else:
        attempt_state, job_state, code = "failed", "failed", "provider_error"
    with transaction(run.store) as conn:
        set_attempt_state(conn, attempt_id, attempt_state, run.now, failure_code=code)
        set_job_state(conn, run.job.job_id, job_state, code, run.now)
    audit_attempt(run.sink, run.job.job_id, attempt_id, attempt_state, failure_code=code)
    return run.outcome(job_state, code, provider_called=True)


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _usage(result: Any) -> Usage:
    """Reported usage; zeros the host fills in for unknown values stay unknown (NULL)."""
    usage = getattr(result, "usage", None)
    cost = getattr(usage, "cost_usd", None)
    known_cost = float(cost) if isinstance(cost, int | float) and not isinstance(cost, bool) else None
    if known_cost is not None and not (math.isfinite(known_cost) and known_cost >= 0):
        known_cost = None
    return Usage(
        _count(getattr(usage, "input_tokens", None)), _count(getattr(usage, "output_tokens", None)), known_cost
    )


def _parsed(result: Any) -> Any:
    parsed = getattr(result, "parsed", None)
    if parsed is not None:
        return parsed
    try:
        return json.loads(getattr(result, "text", None) or "")
    except (TypeError, ValueError):
        return None


def _complete_attempt(
    run: _Run, conn: sqlite3.Connection, attempt_id: str, usage: Usage, actual: tuple[str | None, str | None]
) -> None:
    set_attempt_state(conn, attempt_id, "completed", run.now, usage=usage, actual=actual)


def _audit_completed(run: _Run, attempt_id: str, usage: Usage, actual: tuple[str | None, str | None]) -> None:
    audit_attempt(
        run.sink,
        run.job.job_id,
        attempt_id,
        "completed",
        provider=actual[0],
        model=actual[1],
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
    )


def _close(
    run: _Run,
    attempt_id: str,
    usage: Usage,
    actual: tuple[str | None, str | None],
    job_state: str,
    code: str | None,
) -> ReviewOutcome:
    """Completed attempt (budget consumed) + final job state + reviewed revision, in one transaction."""
    with transaction(run.store) as conn:
        _complete_attempt(run, conn, attempt_id, usage, actual)
        set_job_state(conn, run.job.job_id, job_state, code, run.now)
        if job_state == "completed":
            _advance_reviewed(conn, run.job)
    _audit_completed(run, attempt_id, usage, actual)
    return run.outcome(job_state, code, usage=usage, provider_called=True)


def _advance_reviewed(conn: sqlite3.Connection, job: JobRow) -> None:
    conn.execute(
        "UPDATE activity_episodes SET reviewed_revision = MAX(reviewed_revision, ?) WHERE episode_id = ?",
        (job.input_revision, job.episode_id),
    )


def _candidate_fields(output: ReviewOutput) -> dict[str, Any]:
    return {
        "scope_site": output.scope_site,
        "scope_route": output.scope_route,
        # The reviewer has no task field of its own; its applicability condition names the task.
        "scope_task": output.lesson["applies_when"][:_TASK_LIMIT],
        **{key: output.lesson[key] for key in LESSON_KEYS},
    }


def _lesson_id(created: Any) -> str:
    return str(getattr(created, "lesson_id", created))


def _commit_candidate(
    run: _Run, attempt_id: str, output: ReviewOutput, usage: Usage, actual: tuple[str | None, str | None]
) -> ReviewOutcome:
    """Candidate, completed attempt, completed job and reviewed revision commit together.

    ``lessons.create_candidate_in`` joins this transaction. Without it, the
    attempt's usage commits first and ``lessons.create_candidate`` runs in its
    own transaction; a crash before the job closes leaves it ``calling``
    (reclaimed as ``uncertain``), so no candidate is committed twice automatically.
    """
    from . import lessons

    fields = _candidate_fields(output)
    evidence = list(output.evidence_ids)
    create_in = getattr(lessons, "create_candidate_in", None)
    if create_in is not None:
        with transaction(run.store) as conn:
            created = create_in(
                conn,
                origin="review",
                episode_id=run.job.episode_id,
                fields=fields,
                evidence_event_ids=evidence,
                now=run.now,
            )
            _complete_attempt(run, conn, attempt_id, usage, actual)
            set_job_state(conn, run.job.job_id, "completed", None, run.now)
            _advance_reviewed(conn, run.job)
    else:
        with transaction(run.store) as conn:
            _complete_attempt(run, conn, attempt_id, usage, actual)
        created = lessons.create_candidate(
            run.store, origin="review", episode_id=run.job.episode_id, evidence_event_ids=evidence, **fields
        )
        with transaction(run.store) as conn:
            set_job_state(conn, run.job.job_id, "completed", None, run.now)
            _advance_reviewed(conn, run.job)
    _audit_completed(run, attempt_id, usage, actual)
    return run.outcome("completed", None, lesson_id=_lesson_id(created), usage=usage, provider_called=True)


def _route_mismatch(route: Route, actual: tuple[str | None, str | None], config: ActivityConfig) -> bool:
    if route.kind != "override":
        return False
    provider, model = actual
    return provider != config.review_provider or not (model or "").startswith(config.review_model or "\0")


def _handle_result(run: _Run, attempt_id: str, route: Route, snapshot: Snapshot, result: Any) -> ReviewOutcome:
    usage = _usage(result)
    actual = (bounded_name(getattr(result, "provider", None)), bounded_name(getattr(result, "model", None)))
    if _route_mismatch(route, actual, run.config):
        return _close(run, attempt_id, usage, actual, "failed", "route_mismatch")
    output = validate_output(_parsed(result), snapshot)
    if isinstance(output, OutputRejected):
        # Budget consumed, no repair conversation.
        return _close(run, attempt_id, usage, actual, "failed", output.code)
    if output.decision != "candidate":
        return _close(run, attempt_id, usage, actual, "completed", None)
    try:
        return _commit_candidate(run, attempt_id, output, usage, actual)
    except ActivityRefused as exc:
        if exc.code in _STORE_FAULTS:
            raise
        _LOG.warning("activity review candidate refused (%s, job=%s)", exc.code, run.job.job_id)
        return _close(run, attempt_id, usage, actual, "failed", "candidate_refused")
    except Exception as exc:
        _LOG.warning("activity review candidate refused (%s, job=%s)", type(exc).__name__, run.job.job_id)
        return _close(run, attempt_id, usage, actual, "failed", "candidate_refused")


def _call_kwargs(snapshot: Snapshot, config: ActivityConfig, route: Route) -> dict[str, Any]:
    return {
        "instructions": REVIEW_INSTRUCTIONS,
        "input": [{"type": "text", "text": snapshot.text}],
        "json_schema": OUTPUT_SCHEMA,
        "schema_name": REVIEW_TASK,
        "max_tokens": config.review_max_output_tokens,
        "timeout": config.review_timeout_s,
        "purpose": REVIEW_TASK,
        **route.call_kwargs(),
    }


def _admit(run: _Run, llm: Any, automatic: bool, cancelled: Callable[[], bool] | None) -> tuple[Route, str] | str:
    """Route + reserved attempt, or the refusal code that sends the job back to ``pending``."""
    route = resolve_route(llm, run.config)
    if isinstance(route, Refusal):
        return route.code
    if cancelled is not None and cancelled():
        return "foreground_active"
    reserved = reserve_attempt(
        run.store,
        run.job.job_id,
        route.provider,
        route.model,
        run.config,
        run.now,
        automatic=automatic,
        audit=run.sink,
    )
    return reserved.code if isinstance(reserved, Refusal) else (route, reserved)


def run_review(
    store: ActivityStore,
    *,
    llm: Any,
    job_id: str,
    config: ActivityConfig,
    now: float,
    automatic: bool,
    owner: str,
    excluded_sites: frozenset[str],
    cancelled: Callable[[], bool] | None = None,
    audit: AuditSink | None = None,
) -> ReviewOutcome:
    """Lease, freeze, route, reserve, submit once, validate, commit. Never retries a provider call."""
    sink = audit or _review_jobs.write_audit
    job = get_job(store, job_id)
    if job is None:
        return ReviewOutcome(job_id, "missing", "job_unknown", None, 0)
    if not lease(store, job_id, owner, now, audit=sink):
        return ReviewOutcome(job_id, job.state, "not_leasable", None, job.input_revision)
    run = _Run(store, job, config, now, sink)
    snapshot = _frozen_snapshot(run, excluded_sites)
    if isinstance(snapshot, str):
        return run.finish_job("deferred", snapshot)
    admitted = _admit(run, llm, automatic, cancelled)
    if isinstance(admitted, str):
        return run.finish_job("pending", admitted)
    route, attempt_id = admitted
    _mark_submitted(run, attempt_id)
    try:
        result = llm.complete_structured(**_call_kwargs(snapshot, config, route))
    except Exception as exc:
        return _call_failed(run, attempt_id, exc)
    return _handle_result(run, attempt_id, route, snapshot, result)


def run_one_pending(
    home: Path,
    *,
    llm: Any,
    config: ActivityConfig,
    now: float,
    automatic: bool,
    owner: str,
    cancelled: Callable[[], bool] | None = None,
    audit: AuditSink | None = None,
    store: ActivityStore | None = None,
) -> ReviewOutcome | None:
    """Reclaim stale leases, then review the oldest ``pending`` job (``uncertain`` ones are never picked)."""
    target = store if store is not None else open_review_store(home)
    reclaim_stale(target, now, audit=audit)
    job_id = oldest_pending(target)
    if job_id is None:
        return None
    return run_review(
        target,
        llm=llm,
        job_id=job_id,
        config=config,
        now=now,
        automatic=automatic,
        owner=owner,
        excluded_sites=config.excluded_sites,
        cancelled=cancelled,
        audit=audit,
    )
