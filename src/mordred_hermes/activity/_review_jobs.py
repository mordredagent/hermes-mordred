"""Review jobs, leases, provider-attempt reservations, the rolling budget and the attempt audit."""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import math
import secrets
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlsplit

from ._gate import Refusal, refusal
from ._review_output import REVIEWER_VERSION
from ._review_snapshot import Eligible, build_snapshot, eligible_episodes, transaction
from .config import ActivityConfig

if TYPE_CHECKING:
    from .store import ActivityStore

_LOG = logging.getLogger("mordred.activity.review")

LEASE_TTL_S: Final = 120.0
DAY: Final = 86400.0
_NAME_LIMIT: Final = 128

AuditSink = Callable[[Mapping[str, Any]], None]


def write_audit(entry: Mapping[str, Any]) -> None:
    with contextlib.suppress(Exception):
        from .._audit_support import safe_audit_append
        from ..privacy_check import _runtime

        safe_audit_append(_runtime.ensure_state().audit, entry, logger=_LOG)


def default_audit_sink() -> AuditSink:
    """An audit sink bound now (on the caller's thread) to this process's audit writer."""
    writer: Any = None
    with contextlib.suppress(Exception):
        from ..privacy_check import _runtime

        writer = _runtime.ensure_state().audit
    if writer is None:
        return write_audit

    def sink(entry: Mapping[str, Any]) -> None:
        from .._audit_support import safe_audit_append

        safe_audit_append(writer, entry, logger=_LOG)

    return sink


def audit_attempt(sink: AuditSink, job_id: str, attempt_id: str, state: str, **extra: Any) -> None:
    """``activity.review_attempt``: identifiers, codes and token counts only."""
    entry: dict[str, Any] = {
        "event": "activity.review_attempt",
        "decision": state,
        "reason": "activity.review_attempt",
        "job_id": job_id,
        "attempt_id": attempt_id,
        "state": state,
        "failure_code": extra.get("failure_code"),
        "provider": extra.get("provider"),
        "model": extra.get("model"),
        "input_tokens": extra.get("input_tokens"),
        "output_tokens": extra.get("output_tokens"),
    }
    sink(entry)


def bounded_name(value: Any) -> str | None:
    return value[:_NAME_LIMIT] if isinstance(value, str) and value else None


# --------------------------------------------------------------------------- #
# Jobs and leases
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class JobRow:
    job_id: str
    episode_id: str
    input_revision: int
    state: str
    snapshot_digest: str | None
    failure_code: str | None
    created_at: float
    updated_at: float
    attempts: int = 0


_JOB_COLUMNS: Final = (
    "j.job_id, j.episode_id, j.input_revision, j.state, j.snapshot_digest, j.failure_code, j.created_at, "
    "j.updated_at, (SELECT count(*) FROM activity_review_attempts a WHERE a.job_id = j.job_id)"
)


def _job_from_row(row: Sequence[Any]) -> JobRow:
    return JobRow(
        str(row[0]), str(row[1]), int(row[2]), str(row[3]), row[4], row[5], float(row[6]), float(row[7]), int(row[8])
    )


def get_job(store: ActivityStore, job_id: str) -> JobRow | None:
    with transaction(store, write=False) as conn:
        row = conn.execute(
            f"SELECT {_JOB_COLUMNS} FROM activity_review_jobs j WHERE j.job_id = ?", (job_id,)
        ).fetchone()
    return None if row is None else _job_from_row(row)


def list_jobs(store: ActivityStore, *, states: Sequence[str] = (), limit: int = 50) -> list[JobRow]:
    query = f"SELECT {_JOB_COLUMNS} FROM activity_review_jobs j"
    params: tuple[Any, ...] = ()
    if states:
        query += f" WHERE j.state IN ({', '.join('?' * len(states))})"
        params = tuple(states)
    with transaction(store, write=False) as conn:
        rows = conn.execute(query + " ORDER BY j.created_at, j.job_id LIMIT ?", (*params, max(0, limit))).fetchall()
    return [_job_from_row(row) for row in rows]


def enqueue(
    store: ActivityStore, episode_id: str, revision: int, now: float, *, config: ActivityConfig | None = None
) -> str:
    """The job for ``(episode_id, revision, REVIEWER_VERSION)``; created once with its frozen snapshot digest."""
    cfg = config or ActivityConfig()
    snapshot = build_snapshot(
        store, episode_id, revision, max_input_tokens=cfg.review_max_input_tokens, excluded_sites=cfg.excluded_sites
    )
    with transaction(store) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO activity_review_jobs (job_id, episode_id, input_revision, reviewer_version, "
            "state, snapshot_digest, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)",
            (secrets.token_hex(16), episode_id, revision, REVIEWER_VERSION, snapshot.digest, now, now),
        )
        row = conn.execute(
            "SELECT job_id FROM activity_review_jobs WHERE episode_id = ? AND input_revision = ? "
            "AND reviewer_version = ?",
            (episode_id, revision, REVIEWER_VERSION),
        ).fetchone()
    return str(row[0])


def _fail_reserved(conn: sqlite3.Connection, job_id: str, now: float, sink: AuditSink) -> None:
    """A reservation whose lease lapsed never reached the provider: it is closed as failed."""
    ids = [
        str(row[0])
        for row in conn.execute(
            "SELECT attempt_id FROM activity_review_attempts WHERE job_id = ? AND state = 'reserved'", (job_id,)
        )
    ]
    conn.execute(
        "UPDATE activity_review_attempts SET state = 'failed', failure_code = 'lease_expired', finished_at = ? "
        "WHERE job_id = ? AND state = 'reserved'",
        (now, job_id),
    )
    for attempt_id in ids:
        audit_attempt(sink, job_id, attempt_id, "failed", failure_code="lease_expired")


def lease(
    store: ActivityStore,
    job_id: str,
    owner: str,
    now: float,
    ttl_s: float = LEASE_TTL_S,
    *,
    audit: AuditSink | None = None,
) -> bool:
    """Claim a ``pending`` job, or a ``leased`` one whose lease expired; ``False`` otherwise."""
    with transaction(store) as conn:
        claimed = conn.execute(
            "UPDATE activity_review_jobs SET state = 'leased', lease_owner = ?, lease_expires_at = ?, updated_at = ? "
            "WHERE job_id = ? AND (state = 'pending' OR (state = 'leased' AND lease_expires_at < ?))",
            (owner, now + ttl_s, now, job_id, now),
        ).rowcount
        if claimed == 1:
            _fail_reserved(conn, job_id, now, audit or write_audit)
    return claimed == 1


def reclaim_stale(store: ActivityStore, now: float, *, audit: AuditSink | None = None) -> int:
    """Expired leases return to ``pending``; an expired ``calling`` job becomes ``uncertain``."""
    sink = audit or write_audit
    with transaction(store) as conn:
        leased = [
            str(row[0])
            for row in conn.execute(
                "SELECT job_id FROM activity_review_jobs WHERE state = 'leased' AND lease_expires_at < ?", (now,)
            )
        ]
        calling = [
            str(row[0])
            for row in conn.execute(
                "SELECT job_id FROM activity_review_jobs WHERE state = 'calling' AND lease_expires_at < ?", (now,)
            )
        ]
        for job_id in leased:
            _fail_reserved(conn, job_id, now, sink)
            set_job_state(conn, job_id, "pending", None, now)
        for job_id in calling:
            submitted = [
                str(row[0])
                for row in conn.execute(
                    "SELECT attempt_id FROM activity_review_attempts WHERE job_id = ? AND state = 'submitted'",
                    (job_id,),
                )
            ]
            for attempt_id in submitted:
                set_attempt_state(conn, attempt_id, "uncertain", now, failure_code="lease_expired")
                audit_attempt(sink, job_id, attempt_id, "uncertain", failure_code="lease_expired")
            set_job_state(conn, job_id, "uncertain", "lease_expired", now)
    return len(leased) + len(calling)


def reopen_for_retry(store: ActivityStore, job_id: str, now: float) -> bool:
    """An explicit retry: an ``uncertain`` or ``failed`` job becomes ``pending`` for one new attempt."""
    with transaction(store) as conn:
        changed = conn.execute(
            "UPDATE activity_review_jobs SET state = 'pending', failure_code = NULL, lease_owner = NULL, "
            "lease_expires_at = NULL, updated_at = ? WHERE job_id = ? AND state IN ('uncertain', 'failed')",
            (now, job_id),
        ).rowcount
    return changed == 1


def set_job_state(conn: sqlite3.Connection, job_id: str, state: str, failure_code: str | None, now: float) -> None:
    conn.execute(
        "UPDATE activity_review_jobs SET state = ?, failure_code = ?, lease_owner = NULL, lease_expires_at = NULL, "
        "updated_at = ? WHERE job_id = ?",
        (state, failure_code, now, job_id),
    )


@dataclass(frozen=True)
class ReconcileReport:
    reclaimed: int
    eligible: tuple[Eligible, ...]
    job_ids: tuple[str, ...]


def reconcile_store(
    store: ActivityStore, config: ActivityConfig, now: float, *, audit: AuditSink | None = None
) -> ReconcileReport:
    """Code-only catch-up: reclaim stale leases, enqueue every eligible revision. No model call."""
    reclaimed = reclaim_stale(store, now, audit=audit)
    eligible = tuple(eligible_episodes(store, config, now))
    job_ids = tuple(enqueue(store, item.episode_id, item.revision, now, config=config) for item in eligible)
    return ReconcileReport(reclaimed, eligible, job_ids)


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Usage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


def is_local_route(provider: str | None) -> bool:
    """A provider/base URL on ``localhost`` or a loopback address."""
    if not provider:
        return False
    try:
        host = urlsplit(provider if "://" in provider else f"//{provider}").hostname
    except ValueError:
        return False
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _paid_refusal(conn: sqlite3.Connection, config: ActivityConfig, since: float) -> Refusal | None:
    """Automatic paid work needs an explicit budget, and known costs to measure it against."""
    if config.review_paid_budget_usd is None:
        return refusal("unpriced_route")
    rows = conn.execute(
        "SELECT provider, cost_usd_estimate FROM activity_review_attempts WHERE started_at > ? "
        "AND state IN ('submitted', 'completed', 'uncertain')",
        (since,),
    ).fetchall()
    paid = [cost for provider, cost in rows if not is_local_route(provider)]
    if any(cost is None for cost in paid):
        return refusal("unpriced_route")  # unknown usage is never treated as zero cost
    if sum(float(cost) for cost in paid) >= config.review_paid_budget_usd:
        return refusal("budget_exhausted")
    return None


def _budget_refusal(
    conn: sqlite3.Connection, job_id: str, provider: str | None, config: ActivityConfig, now: float, automatic: bool
) -> Refusal | None:
    since = now - DAY
    count = int(
        conn.execute("SELECT count(*) FROM activity_review_attempts WHERE started_at > ?", (since,)).fetchone()[0]
    )
    if count >= config.review_attempts_per_day:
        return refusal("budget_exhausted")
    if not automatic:
        return None
    if conn.execute("SELECT 1 FROM activity_review_attempts WHERE job_id = ?", (job_id,)).fetchone():
        return refusal("attempt_limit")  # at most one automatic attempt per job
    last = conn.execute("SELECT max(started_at) FROM activity_review_attempts").fetchone()[0]
    if last is not None and now - float(last) < config.review_min_spacing_s:
        return refusal("spacing")
    return None if is_local_route(provider) else _paid_refusal(conn, config, since)


def _touch_budget(conn: sqlite3.Connection, now: float, *, attempts: int = 0, used_cost: float = 0.0) -> None:
    start = math.floor(now / DAY) * DAY
    conn.execute(
        "INSERT INTO activity_budget (window_start, window_end, attempts, used_cost_usd) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (window_start) DO UPDATE SET attempts = attempts + excluded.attempts, "
        "used_cost_usd = used_cost_usd + excluded.used_cost_usd",
        (start, start + DAY, attempts, used_cost),
    )


def reserve_attempt(
    store: ActivityStore,
    job_id: str,
    provider: str | None,
    model: str | None,
    config: ActivityConfig,
    now: float,
    *,
    automatic: bool,
    audit: AuditSink | None = None,
) -> str | Refusal:
    """Reserve and persist one physical provider attempt, or refuse with a content-free code.

    The cost estimate stays unknown (``cost_usd_estimate`` NULL) until the
    host reports one; there is no price table, so unknown never means zero.
    """
    with transaction(store) as conn:
        found = _budget_refusal(conn, job_id, provider, config, now, automatic)
        if found is not None:
            return found
        attempt_id = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO activity_review_attempts (attempt_id, job_id, request_id, provider, model, "
            "reserved_input_tokens, reserved_output_tokens, cost_usd_estimate, state, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'reserved', ?)",
            (
                attempt_id,
                job_id,
                secrets.token_hex(16),
                bounded_name(provider),
                bounded_name(model),
                config.review_max_input_tokens,
                config.review_max_output_tokens,
                now,
            ),
        )
        _touch_budget(conn, now, attempts=1)
    audit_attempt(
        audit or write_audit, job_id, attempt_id, "reserved", provider=bounded_name(provider), model=bounded_name(model)
    )
    return attempt_id


def set_attempt_state(
    conn: sqlite3.Connection,
    attempt_id: str,
    state: str,
    now: float,
    *,
    failure_code: str | None = None,
    usage: Usage | None = None,
    actual: tuple[str | None, str | None] = (None, None),
) -> None:
    used = usage or Usage()
    conn.execute(
        "UPDATE activity_review_attempts SET state = ?, failure_code = ?, finished_at = ?, "
        "usage_input_tokens = COALESCE(?, usage_input_tokens), usage_output_tokens = COALESCE(?, usage_output_tokens), "
        "cost_usd_estimate = COALESCE(?, cost_usd_estimate), provider = COALESCE(?, provider), "
        "model = COALESCE(?, model) WHERE attempt_id = ?",
        (state, failure_code, now, used.input_tokens, used.output_tokens, used.cost_usd, *actual, attempt_id),
    )
    if used.cost_usd is not None:
        _touch_budget(conn, now, used_cost=used.cost_usd)


def oldest_pending(store: ActivityStore) -> str | None:
    with transaction(store, write=False) as conn:
        row = conn.execute(
            "SELECT job_id FROM activity_review_jobs WHERE state = 'pending' AND reviewer_version = ? "
            "ORDER BY created_at, job_id LIMIT 1",
            (REVIEWER_VERSION,),
        ).fetchone()
    return None if row is None else str(row[0])
