"""``hermes-mordred activity review|jobs`` — explicit, budgeted activity review.

- ``review --dry-run [--json]`` — code-only reconcile (reclaim stale leases,
  enqueue eligible episodes), then print eligible episodes, pending/uncertain
  jobs and the resolved route or its refusal. No model call.
- ``review [--episode ID | --retry JOB_ID] [--json]`` — reconcile, then one
  explicit review of the selected episode's job, a retried ``uncertain`` /
  ``failed`` job (a new attempt), or the oldest pending job. It may make one
  live provider call under the configured budget; the output says so and
  reports the recorded token counts.
- ``jobs list [--json]`` — review jobs (identifiers, states, codes, counts).

Output carries identifiers, states, codes and counts only — never snapshot,
lesson or model text.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import _term

if TYPE_CHECKING:
    from ..activity.config import ActivityConfig
    from ..activity.review import ReviewOutcome
    from ..activity.store import ActivityStore

__all__ = ["add_parsers", "handle"]

_SHOWN_JOB_STATES = ("pending", "uncertain")


def add_parsers(asub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Add ``review`` and ``jobs list`` to the ``activity`` subcommand group."""
    p_review = asub.add_parser("review", help="Run one explicit activity review (--dry-run: no model call)")
    target = p_review.add_mutually_exclusive_group()
    target.add_argument("--episode", metavar="ID", help="Review this episode's current revision")
    target.add_argument("--retry", metavar="JOB_ID", help="New explicit attempt for an uncertain or failed job")
    p_review.add_argument("--dry-run", action="store_true", help="Reconcile and show what would run; no model call")
    p_review.add_argument("--json", action="store_true", help="Print one JSON object")
    p_review.set_defaults(func=handle, activity_review_command="review")
    p_jobs = asub.add_parser("jobs", help="Activity review jobs")
    jsub = p_jobs.add_subparsers(dest="activity_jobs_command", required=True, metavar="COMMAND")
    p_list = jsub.add_parser("list", help="List review jobs (identifiers, states, codes)")
    p_list.add_argument("--json", action="store_true", help="Print one JSON object")
    p_list.set_defaults(func=handle, activity_review_command="jobs_list")


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _display(value: object, limit: int = 80) -> str:
    """Same-user-writable state is escaped before it reaches the terminal."""
    text = str(value)[:limit]
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, default=str))


def _refused(code: str, *, as_json: bool) -> int:
    if as_json:
        _emit_json({"status": "refused", "code": code})
    else:
        _term.emit_error(f"activity review refused ({_display(code)})")
    return 1


def _job_dict(job: Any) -> dict[str, Any]:
    return {key: value for key, value in asdict(job).items() if key != "snapshot_digest"}


# --------------------------------------------------------------------------- #
# jobs list
# --------------------------------------------------------------------------- #


def _jobs_list(store: ActivityStore, *, as_json: bool) -> int:
    from ..activity import review

    jobs = [_job_dict(job) for job in review.list_jobs(store, limit=100)]
    if as_json:
        _emit_json({"status": "ok", "jobs": jobs})
        return 0
    color = _term.should_color(sys.stdout)
    print(_term.heading("Mordred activity review jobs", enabled=color))
    if not jobs:
        print("  (none)")
    for job in jobs:
        code = f" ({_display(job['failure_code'])})" if job["failure_code"] else ""
        print(
            f"  {_display(job['job_id'])}  episode {_display(job['episode_id'])} rev {job['input_revision']}  "
            f"{_display(job['state'])}{code}  attempts {job['attempts']}"
        )
    return 0


# --------------------------------------------------------------------------- #
# review --dry-run
# --------------------------------------------------------------------------- #


def _route_label(config: ActivityConfig) -> str:
    """``task`` / ``override`` or the refusal code; constructing the facade makes no call."""
    from ..activity import review
    from ..activity._gate import Refusal

    llm = review.resolve_llm()
    if isinstance(llm, Refusal):
        return llm.code
    route = review.resolve_route(llm, config)
    return route.code if isinstance(route, Refusal) else route.kind


def _dry_run(store: ActivityStore, config: ActivityConfig, now: float, *, as_json: bool) -> int:
    from ..activity import review

    report = review.reconcile_store(store, config, now)
    jobs = [_job_dict(job) for job in review.list_jobs(store, states=_SHOWN_JOB_STATES, limit=100)]
    payload = {
        "status": "dry_run",
        "model_called": False,
        "reclaimed": report.reclaimed,
        "eligible": [asdict(item) for item in report.eligible],
        "jobs": jobs,
        "route": _route_label(config),
    }
    if as_json:
        _emit_json(payload)
        return 0
    color = _term.should_color(sys.stdout)
    print(_term.heading("Mordred activity review (dry run)", enabled=color))
    print(f"Route:            {_display(payload['route'])}")
    print(f"Leases reclaimed: {report.reclaimed}")
    print(f"Eligible episodes ({len(report.eligible)}):")
    for item in report.eligible:
        print(f"  {_display(item.episode_id)}  rev {item.revision}  {_display(item.signal)}")
    print(f"Pending / uncertain jobs ({len(jobs)}):")
    for job in jobs:
        print(f"  {_display(job['job_id'])}  episode {_display(job['episode_id'])}  {_display(job['state'])}")
    print("No model call was made.")
    return 0


# --------------------------------------------------------------------------- #
# review (explicit)
# --------------------------------------------------------------------------- #


def _select_job(store: ActivityStore, config: ActivityConfig, args: argparse.Namespace, now: float) -> str:
    """The job to run, or a refusal code prefixed with ``!``."""
    from ..activity import review

    if args.retry:
        if review.get_job(store, str(args.retry)) is None:
            return "!job_unknown"
        return str(args.retry) if review.reopen_for_retry(store, str(args.retry), now) else "!not_retryable"
    if args.episode:
        episode = store.episode(str(args.episode))
        if episode is None:
            return "!episode_unknown"
        job_id = review.enqueue(store, episode.episode_id, episode.revision, now, config=config)
        job = review.get_job(store, job_id)
        return job_id if job is not None and job.state == "pending" else "!job_not_pending"
    return review.oldest_pending(store) or "!no_pending_job"


def _print_outcome(outcome: ReviewOutcome, *, as_json: bool) -> None:
    usage = outcome.usage
    if as_json:
        _emit_json({"status": "ran", **asdict(outcome)})
        return
    color = _term.should_color(sys.stdout)
    print(_term.heading("Mordred activity review", enabled=color))
    print(f"Job:      {_display(outcome.job_id)} (episode revision {outcome.revision})")
    code = f" ({_display(outcome.failure_code)})" if outcome.failure_code else ""
    print(f"State:    {_display(outcome.state)}{code}")
    if outcome.lesson_id:
        print(f"Candidate lesson: {_display(outcome.lesson_id)} (review it with the lesson commands)")
    if outcome.provider_called:
        counts = f"input tokens {usage.input_tokens or 'unknown'}, output tokens {usage.output_tokens or 'unknown'}"
        _term.emit_note(f"a live provider call was made ({counts})")
    else:
        print("No provider call was made.")


def _review(store: ActivityStore, config: ActivityConfig, args: argparse.Namespace, now: float) -> int:
    from ..activity import review
    from ..activity._gate import Refusal

    llm = review.resolve_llm()
    if isinstance(llm, Refusal):
        return _refused(llm.code, as_json=args.json)
    review.reconcile_store(store, config, now)
    selected = _select_job(store, config, args, now)
    if selected.startswith("!"):
        return _refused(selected[1:], as_json=args.json)
    outcome = review.run_review(
        store,
        llm=llm,
        job_id=selected,
        config=config,
        now=now,
        automatic=False,
        owner=f"cli:{os.getpid()}",
        excluded_sites=config.excluded_sites,
    )
    _print_outcome(outcome, as_json=args.json)
    return 0 if outcome.state == "completed" else 1


def handle(args: argparse.Namespace) -> int:
    from ..activity import review
    from ..activity._gate import ActivityRefused
    from ..activity.config import ActivityConfig

    home = _home()
    as_json = bool(getattr(args, "json", False))
    try:
        store = review.open_review_store(home)
        if args.activity_review_command == "jobs_list":
            return _jobs_list(store, as_json=as_json)
        config = ActivityConfig.load(home)
        if not config.enabled:
            return _refused("feature_disabled", as_json=as_json)
        now = time.time()
        if args.dry_run:
            return _dry_run(store, config, now, as_json=as_json)
        return _review(store, config, args, now)
    except ActivityRefused as exc:
        return _refused(exc.code, as_json=as_json)
