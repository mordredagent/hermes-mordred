"""Behaviour contract of conditional review: jobs, eligibility, budget, routing, validation, commit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _review_jobs, _review_run, review
from mordred_hermes.activity._gate import Refusal
from mordred_hermes.activity.store import ActivityStore
from tests._activity_review_helpers import (
    SITE,
    FakeLessons,
    LegacyLlm,
    TaskLlm,
    answer,
    append,
    completed_episode,
    config,
    correction_episode,
    event,
    make_store,
    result,
    rows,
    verified,
)

NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def lenient_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_review_run, "_policy_mode", lambda: "lenient")


@pytest.fixture(autouse=True)
def audit(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    monkeypatch.setattr(_review_jobs, "write_audit", lambda entry: entries.append(dict(entry)))
    return entries


@pytest.fixture
def store(tmp_path: Path) -> ActivityStore:
    return make_store(tmp_path)


@pytest.fixture
def fake_lessons(monkeypatch: pytest.MonkeyPatch) -> FakeLessons:
    return FakeLessons().install(monkeypatch)


def _job(store: ActivityStore, episode: str = "ep-corr", **cfg: Any) -> str:
    current = store.episode(episode)
    assert current is not None
    return review.enqueue(store, episode, current.revision, NOW, config=config(**cfg))


def _run(store: ActivityStore, llm: Any, job_id: str, *, automatic: bool = False, **cfg: Any) -> review.ReviewOutcome:
    settings = config(**cfg)
    return review.run_review(
        store,
        llm=llm,
        job_id=job_id,
        config=settings,
        now=NOW,
        automatic=automatic,
        owner="test",
        excluded_sites=settings.excluded_sites,
    )


def _evidence(store: ActivityStore, episode: str = "ep-corr") -> list[str]:
    return [item.event_id for item in store.events_for_episode(episode)]


# --------------------------------------------------------------------------- #
# Jobs and leases
# --------------------------------------------------------------------------- #


def test_enqueue_is_idempotent_per_episode_revision_and_reviewer(store: ActivityStore) -> None:
    correction_episode(store)
    first = review.enqueue(store, "ep-corr", 1, NOW)
    again = review.enqueue(store, "ep-corr", 1, NOW + 5)
    append(store, event("ep-corr"))
    later = review.enqueue(store, "ep-corr", 2, NOW + 10)

    assert first == again != later
    assert rows(store, "SELECT input_revision, state, reviewer_version FROM activity_review_jobs ORDER BY 1") == [
        (1, "pending", review.REVIEWER_VERSION),
        (2, "pending", review.REVIEWER_VERSION),
    ]


def test_lease_is_exclusive_until_it_expires_and_reclaim_returns_it(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = review.enqueue(store, "ep-corr", 1, NOW)

    assert review.lease(store, job_id, "a", NOW, ttl_s=60)
    assert not review.lease(store, job_id, "b", NOW + 30)
    assert review.reclaim_stale(store, NOW + 30) == 0
    assert review.reclaim_stale(store, NOW + 61) == 1
    assert rows(store, "SELECT state, lease_owner FROM activity_review_jobs") == [("pending", None)]
    assert review.lease(store, job_id, "b", NOW + 62)
    assert review.lease(store, job_id, "c", NOW + 62 + review.LEASE_TTL_S + 1)  # expired lease taken over


def test_reclaim_turns_an_expired_calling_job_uncertain(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = review.enqueue(store, "ep-corr", 1, NOW)
    assert review.lease(store, job_id, "a", NOW)
    attempt = review.reserve_attempt(store, job_id, "openrouter", "m", config(), NOW, automatic=False)
    assert isinstance(attempt, str)
    with store.connection() as conn:
        conn.execute("UPDATE activity_review_jobs SET state = 'calling', lease_expires_at = ?", (NOW + 1,))
        conn.execute("UPDATE activity_review_attempts SET state = 'submitted'")

    assert review.reclaim_stale(store, NOW + 2) == 1
    assert rows(store, "SELECT state, failure_code FROM activity_review_jobs") == [("uncertain", "lease_expired")]
    assert rows(store, "SELECT state FROM activity_review_attempts") == [("uncertain",)]


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #


def test_correction_is_eligible_but_time_and_volume_alone_are_not(store: ActivityStore) -> None:
    correction_episode(store)
    append(store, *[event("ep-busy") for _ in range(40)])

    found = review.eligible_episodes(store, config(), NOW + 365 * 86400)

    assert [(item.episode_id, item.signal) for item in found] == [("ep-corr", "correction")]


def test_verified_failure_then_success_of_the_same_step_is_eligible(store: ActivityStore) -> None:
    append(
        store,
        verified(event("ep-fix", route="/save"), "verified_failure"),
        event("ep-fix", route="/save", status="claimed_success"),
    )
    append(store, verified(event("ep-other", route="/a"), "verified_failure"), event("ep-other", route="/b"))

    found = review.eligible_episodes(store, config(), NOW)

    assert [(item.episode_id, item.signal) for item in found] == [("ep-fix", "failure_recovery")]


def test_repeated_procedure_needs_three_distinct_completed_episodes(store: ActivityStore) -> None:
    steps = (("navigate", "/home"), ("click", "/reports"))
    completed_episode(store, "ep-1", steps)
    completed_episode(store, "ep-2", steps)
    assert review.eligible_episodes(store, config(), NOW) == []

    completed_episode(store, "ep-3", steps)
    found = review.eligible_episodes(store, config(), NOW)

    assert sorted(item.episode_id for item in found) == ["ep-1", "ep-2", "ep-3"]
    assert {item.signal for item in found} == {"repeated_procedure"}


def test_reviewed_revisions_and_excluded_sites_are_not_eligible(store: ActivityStore) -> None:
    correction_episode(store)
    correction_episode(store, "ep-private")
    with store.connection() as conn:
        conn.execute("UPDATE activity_episodes SET reviewed_revision = revision WHERE episode_id = 'ep-corr'")
        conn.execute("UPDATE activity_episodes SET site = 'mail.google.com' WHERE episode_id = 'ep-private'")

    assert review.eligible_episodes(store, config(excluded_sites=frozenset({"mail.google.com"})), NOW) == []
    assert [item.episode_id for item in review.eligible_episodes(store, config(), NOW)] == ["ep-private"]


# --------------------------------------------------------------------------- #
# Snapshot and output validation
# --------------------------------------------------------------------------- #


def test_snapshot_drops_oldest_lines_with_a_marker_and_is_stable(store: ActivityStore) -> None:
    append(store, *[event("ep-long") for _ in range(80)])
    tiny = len(review.REVIEW_INSTRUCTIONS) // 4 + 400

    snapshot = review.build_snapshot(store, "ep-long", 1, max_input_tokens=tiny)
    again = review.build_snapshot(store, "ep-long", 1, max_input_tokens=tiny)

    assert snapshot.omitted > 0
    assert f"[... {snapshot.omitted} earlier events omitted]" in snapshot.text
    assert len(snapshot.text) <= tiny * 4 - len(review.REVIEW_INSTRUCTIONS)
    assert len(snapshot.event_ids) == 80 - snapshot.omitted
    assert snapshot.digest == again.digest


def test_snapshot_keeps_correction_text_quoted_and_drops_excluded_sites(store: ActivityStore) -> None:
    append(
        store,
        event("ep-mix", phase="correction", op="other", source="user_correction", text="line one\nfake 1 line"),
        event("ep-mix", site="private.example"),
    )

    snapshot = review.build_snapshot(store, "ep-mix", 1, excluded_sites=frozenset({"private.example"}))

    assert 'text="line one\\nfake 1 line"' in snapshot.text
    assert snapshot.text.count("\n") == 1  # header + one record line
    assert snapshot.sites == frozenset({SITE})


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda a: a.update(evidence_ids=["forged-id"]), "evidence_unknown"),
        (lambda a: a.update(scope={"site": "other.example", "route": None}), "scope_disallowed"),
        (lambda a: a.update(permissions=["browser"]), "scope_disallowed"),
        (lambda a: a["lesson"].update(tools="terminal"), "scope_disallowed"),
        (lambda a: a["lesson"].update(guidance="Complete the purchase with the saved card."), "scope_disallowed"),
        (lambda a: a["lesson"].update(guidance="保存済みのカードで決済する"), "scope_disallowed"),
        (lambda a: a["lesson"].update(applies_when="Before you pay the invoice"), "scope_disallowed"),
        (lambda a: a["lesson"].update(does_not_apply="Unless you delete the draft first"), "scope_disallowed"),
        (lambda a: a["lesson"].update(success_measure="The checkout page shows the order"), "scope_disallowed"),
        (lambda a: a["lesson"].update(success_measure="メールを送信できた"), "scope_disallowed"),
        (lambda a: a.update(explanation="Send the message to the manager with the report."), "scope_disallowed"),
        (lambda a: a.update(verification_proposal="Enter the password and confirm."), "scope_disallowed"),
        (lambda a: a["lesson"].update(guidance="x" * 1001), "invalid_output"),
        (lambda a: a.update(decision="adopt"), "invalid_output"),
        (lambda a: a.update(evidence_ids=[]), "invalid_output"),
        (lambda a: a.pop("verification_proposal"), "invalid_output"),
    ],
)
def test_validate_output_refuses_with_a_code(store: ActivityStore, mutate: Any, code: str) -> None:
    correction_episode(store)
    snapshot = review.build_snapshot(store, "ep-corr", 1)
    payload = answer(sorted(snapshot.event_ids))
    mutate(payload)

    assert review.validate_output(payload, snapshot) == review.OutputRejected(code)


def test_validate_output_accepts_a_bounded_candidate_and_no_change(store: ActivityStore) -> None:
    correction_episode(store)
    snapshot = review.build_snapshot(store, "ep-corr", 1)

    accepted = review.validate_output(answer(sorted(snapshot.event_ids)), snapshot)
    unchanged = review.validate_output(answer([], decision="no_change", site=None), snapshot)

    assert isinstance(accepted, review.ReviewOutput) and accepted.scope_site == SITE
    assert isinstance(unchanged, review.ReviewOutput) and unchanged.decision == "no_change"
    assert review.validate_output("not an object", snapshot) == review.OutputRejected("invalid_output")


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #


def test_third_attempt_in_24h_is_refused_even_when_explicit(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = review.enqueue(store, "ep-corr", 1, NOW)
    cfg = config()

    first = review.reserve_attempt(store, job_id, "openrouter", "m", cfg, NOW, automatic=False)
    second = review.reserve_attempt(store, job_id, "openrouter", "m", cfg, NOW + 1, automatic=False)
    third = review.reserve_attempt(store, job_id, "openrouter", "m", cfg, NOW + 2, automatic=False)
    next_day = review.reserve_attempt(store, job_id, "openrouter", "m", cfg, NOW + 86_401, automatic=False)

    assert isinstance(first, str) and isinstance(second, str) and isinstance(next_day, str)
    assert third == Refusal("budget_exhausted", "budget exhausted")
    assert rows(
        store,
        "SELECT reserved_input_tokens, reserved_output_tokens, cost_usd_estimate FROM activity_review_attempts LIMIT 1",
    ) == [(6000, 1000, None)]
    assert rows(store, "SELECT sum(attempts) FROM activity_budget") == [(3,)]


def test_spacing_and_unpriced_routes_refuse_only_automatic_attempts(store: ActivityStore) -> None:
    correction_episode(store)
    correction_episode(store, "ep-2")
    first_job = review.enqueue(store, "ep-corr", 1, NOW)
    second_job = review.enqueue(store, "ep-2", 1, NOW)
    cfg = config(review_attempts_per_day=10)

    unpriced = review.reserve_attempt(store, first_job, "openrouter", "m", cfg, NOW, automatic=True)
    explicit = review.reserve_attempt(store, first_job, "openrouter", "m", cfg, NOW, automatic=False)
    spaced = review.reserve_attempt(store, second_job, "http://127.0.0.1:11434", "m", cfg, NOW + 60, automatic=True)
    local = review.reserve_attempt(store, second_job, "http://127.0.0.1:11434", "m", cfg, NOW + 1801, automatic=True)
    once = review.reserve_attempt(store, second_job, "localhost:11434", "m", cfg, NOW + 4000, automatic=True)

    assert isinstance(unpriced, Refusal) and unpriced.code == "unpriced_route"
    assert isinstance(explicit, str)
    assert isinstance(spaced, Refusal) and spaced.code == "spacing"
    assert isinstance(local, str)
    assert isinstance(once, Refusal) and once.code == "attempt_limit"


def test_unknown_cost_blocks_further_paid_automatic_attempts(store: ActivityStore) -> None:
    correction_episode(store)
    correction_episode(store, "ep-2")
    first_job = review.enqueue(store, "ep-corr", 1, NOW)
    second_job = review.enqueue(store, "ep-2", 1, NOW)
    cfg = config(review_paid_budget_usd=1.0, review_attempts_per_day=10)

    paid = review.reserve_attempt(store, first_job, "openrouter", "m", cfg, NOW, automatic=True)
    with store.connection() as conn:
        conn.execute("UPDATE activity_review_attempts SET state = 'completed'")
    again = review.reserve_attempt(store, second_job, "openrouter", "m", cfg, NOW + 1801, automatic=True)

    assert isinstance(paid, str)
    assert isinstance(again, Refusal) and again.code == "unpriced_route"


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


def test_task_capable_facade_routes_through_the_registered_task() -> None:
    assert review.resolve_route(TaskLlm(), config(review_provider=None, review_model=None)) == review.Route(
        "task", task=review.REVIEW_TASK
    )


def test_legacy_facade_needs_an_explicit_provider_and_model() -> None:
    assert review.resolve_route(LegacyLlm(), config()) == review.Route(
        "override", provider="openrouter", model="vendor/model-a"
    )
    refused = review.resolve_route(LegacyLlm(), config(review_model=None))
    assert isinstance(refused, Refusal) and refused.code == "route_unavailable"


def test_strict_policy_without_the_auxiliary_guard_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_review_run, "_policy_mode", lambda: "strict")
    monkeypatch.setattr(_review_run, "_guard_installed", lambda: False)
    refused = review.resolve_route(TaskLlm(), config())
    assert isinstance(refused, Refusal) and refused.code == "guard_unavailable"

    monkeypatch.setattr(_review_run, "_guard_installed", lambda: True)
    assert isinstance(review.resolve_route(TaskLlm(), config()), review.Route)


def test_is_local_route() -> None:
    assert review.is_local_route("http://127.0.0.1:11434/v1")
    assert review.is_local_route("localhost:8080")
    assert review.is_local_route("http://[::1]:1")
    assert not review.is_local_route("openrouter")
    assert not review.is_local_route("https://api.example.com")
    assert not review.is_local_route(None)


# --------------------------------------------------------------------------- #
# The run
# --------------------------------------------------------------------------- #


def test_valid_candidate_commits_one_lesson_and_one_completed_attempt(
    store: ActivityStore, fake_lessons: FakeLessons, audit: list[dict[str, Any]]
) -> None:
    correction_episode(store)
    job_id = _job(store)
    llm = TaskLlm(result(answer(_evidence(store))))

    outcome = _run(store, llm, job_id)

    assert outcome.state == "completed" and outcome.lesson_id is not None
    assert len(llm.calls) == 1
    call = llm.calls[0]
    assert call["task"] == review.REVIEW_TASK and call["provider"] is None
    assert call["json_schema"] == review.OUTPUT_SCHEMA and call["purpose"] == review.REVIEW_TASK
    assert (call["max_tokens"], call["timeout"]) == (1000, 30)
    assert rows(store, "SELECT count(*), origin FROM activity_lessons") == [(1, "review")]
    assert rows(
        store,
        "SELECT state, usage_input_tokens, usage_output_tokens, cost_usd_estimate, provider "
        "FROM activity_review_attempts",
    ) == [("completed", 812, 140, None, "openrouter")]
    assert rows(store, "SELECT reviewed_revision FROM activity_episodes") == [(1,)]
    assert fake_lessons.calls[0]["origin"] == "review"
    assert fake_lessons.calls[0]["evidence_event_ids"] == _evidence(store)
    assert [entry["state"] for entry in audit] == ["reserved", "submitted", "completed"]
    text = repr(audit)
    assert "account switcher" not in text and "Open the account" not in text


def test_candidate_commit_without_a_joinable_creator_is_still_single(
    store: ActivityStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    lessons = FakeLessons(joins_transaction=False).install(monkeypatch)
    correction_episode(store)
    job_id = _job(store)

    outcome = _run(store, LegacyLlm(result(answer(_evidence(store)))), job_id)

    assert outcome.state == "completed" and len(lessons.calls) == 1
    assert rows(store, "SELECT count(*) FROM activity_lessons") == [(1,)]
    assert rows(store, "SELECT state FROM activity_review_jobs") == [("completed",)]


def test_a_refused_candidate_fails_the_job_and_keeps_the_usage(
    store: ActivityStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.activity._gate import ActivityRefused, refusal

    FakeLessons(fail=ActivityRefused(refusal("invalid_field"))).install(monkeypatch)
    correction_episode(store)
    job_id = _job(store)

    outcome = _run(store, LegacyLlm(result(answer(_evidence(store)))), job_id)

    assert (outcome.state, outcome.failure_code) == ("failed", "candidate_refused")
    assert rows(store, "SELECT state, usage_input_tokens FROM activity_review_attempts") == [("completed", 812)]
    assert rows(store, "SELECT count(*) FROM activity_lessons") == [(0,)]


def test_no_change_completes_without_a_lesson(store: ActivityStore, fake_lessons: FakeLessons) -> None:
    correction_episode(store)
    job_id = _job(store)

    outcome = _run(store, LegacyLlm(result(answer([], decision="no_change", site=None))), job_id)

    assert (outcome.state, outcome.lesson_id) == ("completed", None)
    assert fake_lessons.calls == []
    assert rows(store, "SELECT reviewed_revision FROM activity_episodes") == [(1,)]


@pytest.mark.parametrize(
    ("reply", "code"),
    [
        (result(None, text="I think the user wanted reports"), "invalid_output"),
        (result(answer(["forged-event-id"])), "evidence_unknown"),
        (result(answer([], site="bank.example")), "scope_disallowed"),
        (result({**answer([]), "permissions": ["payments"]}), "scope_disallowed"),
    ],
)
def test_bad_output_fails_the_job_and_consumes_the_attempt(
    store: ActivityStore, fake_lessons: FakeLessons, reply: Any, code: str
) -> None:
    correction_episode(store)
    job_id = _job(store)
    if code == "scope_disallowed" and reply.parsed.get("evidence_ids") == []:
        reply.parsed["evidence_ids"] = _evidence(store)
    llm = LegacyLlm(reply)

    outcome = _run(store, llm, job_id)

    assert (outcome.state, outcome.failure_code) == ("failed", code)
    assert len(llm.calls) == 1  # no repair conversation
    assert rows(store, "SELECT state, usage_input_tokens FROM activity_review_attempts") == [("completed", 812)]
    assert fake_lessons.calls == []
    assert rows(store, "SELECT reviewed_revision FROM activity_episodes") == [(0,)]


def test_override_route_mismatch_fails(store: ActivityStore, fake_lessons: FakeLessons) -> None:
    correction_episode(store)
    job_id = _job(store)

    outcome = _run(store, LegacyLlm(result(answer(_evidence(store)), provider="anthropic")), job_id)

    assert (outcome.state, outcome.failure_code) == ("failed", "route_mismatch")
    assert fake_lessons.calls == []


def test_unknown_usage_is_recorded_as_unknown_not_zero(store: ActivityStore, fake_lessons: FakeLessons) -> None:
    correction_episode(store)
    job_id = _job(store)

    _run(store, LegacyLlm(result(answer([], decision="no_change", site=None), tokens=(0, 0))), job_id)

    assert rows(store, "SELECT usage_input_tokens, usage_output_tokens FROM activity_review_attempts") == [(None, None)]


def test_timeout_is_uncertain_and_never_resubmitted(store: ActivityStore, tmp_path: Path) -> None:
    correction_episode(store)
    job_id = _job(store)
    llm = LegacyLlm(error=TimeoutError("request timed out"))

    outcome = _run(store, llm, job_id)
    again = review.run_one_pending(
        tmp_path, llm=llm, config=config(), now=NOW + 7200, automatic=True, owner="auto", store=store
    )

    assert (outcome.state, outcome.failure_code) == ("uncertain", "timeout")
    assert rows(store, "SELECT state, failure_code FROM activity_review_attempts") == [("uncertain", "timeout")]
    assert again is None and len(llm.calls) == 1


def test_provider_error_fails_without_retry(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = _job(store)
    llm = LegacyLlm(error=RuntimeError("upstream said: secret prompt text"))

    outcome = _run(store, llm, job_id)

    assert (outcome.state, outcome.failure_code) == ("failed", "provider_error")
    assert rows(store, "SELECT state, failure_code FROM activity_review_attempts") == [("failed", "provider_error")]


def test_revision_moved_after_enqueue_defers_without_a_call(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = _job(store)
    append(store, event("ep-corr"))
    llm = LegacyLlm(result(answer(_evidence(store))))

    outcome = _run(store, llm, job_id)

    assert (outcome.state, outcome.failure_code) == ("deferred", "evidence_changed")
    assert llm.calls == [] and rows(store, "SELECT count(*) FROM activity_review_attempts") == [(0,)]


def test_changed_snapshot_defers(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = _job(store)
    with store.connection() as conn:
        conn.execute("DELETE FROM activity_events WHERE phase = 'dispatched'")  # retention removed evidence

    outcome = _run(store, LegacyLlm(), job_id)

    assert (outcome.state, outcome.failure_code) == ("deferred", "snapshot_changed")


def test_admission_refusal_leaves_the_job_pending(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = _job(store)
    llm = LegacyLlm(result(answer(_evidence(store))))

    outcome = _run(store, llm, job_id, automatic=True)  # paid route, no budget configured

    assert (outcome.state, outcome.failure_code) == ("pending", "unpriced_route")
    assert llm.calls == [] and rows(store, "SELECT state FROM activity_review_jobs") == [("pending",)]


def test_cancelled_by_new_foreground_input_submits_nothing(store: ActivityStore) -> None:
    correction_episode(store)
    job_id = _job(store)
    llm = LegacyLlm(result(answer(_evidence(store))))
    settings = config()

    outcome = review.run_review(
        store,
        llm=llm,
        job_id=job_id,
        config=settings,
        now=NOW,
        automatic=False,
        owner="t",
        excluded_sites=settings.excluded_sites,
        cancelled=lambda: True,
    )

    assert (outcome.state, outcome.failure_code) == ("pending", "foreground_active")
    assert llm.calls == []


def test_run_one_pending_skips_restored_uncertain_jobs(store: ActivityStore, tmp_path: Path) -> None:
    correction_episode(store)
    job_id = _job(store)
    with store.connection() as conn:
        conn.execute("UPDATE activity_review_jobs SET state = 'uncertain' WHERE job_id = ?", (job_id,))
    llm = LegacyLlm(result(answer(_evidence(store))))

    assert (
        review.run_one_pending(tmp_path, llm=llm, config=config(), now=NOW, automatic=False, owner="t", store=store)
        is None
    )
    assert llm.calls == []


def test_explicit_retry_reopens_an_uncertain_job_for_one_new_attempt(
    store: ActivityStore, fake_lessons: FakeLessons
) -> None:
    correction_episode(store)
    job_id = _job(store)
    _run(store, LegacyLlm(error=TimeoutError()), job_id)

    assert review.reopen_for_retry(store, job_id, NOW + 1)
    outcome = _run(store, LegacyLlm(result(answer(_evidence(store)))), job_id)

    assert outcome.state == "completed"
    assert rows(store, "SELECT state FROM activity_review_attempts ORDER BY started_at, state") == [
        ("completed",),
        ("uncertain",),
    ]
    assert not review.reopen_for_retry(store, job_id, NOW + 2)  # completed jobs are final


def test_real_lessons_module_commits_a_review_candidate(store: ActivityStore) -> None:
    lessons = pytest.importorskip("mordred_hermes.activity.lessons")
    if not hasattr(lessons, "create_candidate_in") and not hasattr(lessons, "create_candidate"):
        pytest.skip("lessons module without a candidate creator")
    correction_episode(store)
    job_id = _job(store)

    outcome = _run(store, LegacyLlm(result(answer(_evidence(store)))), job_id)

    assert outcome.state == "completed"
    assert rows(store, "SELECT state, origin, scope_site FROM activity_lessons") == [("candidate", "review", SITE)]
    assert rows(store, "SELECT count(*) FROM activity_lesson_evidence") == [(2,)]
