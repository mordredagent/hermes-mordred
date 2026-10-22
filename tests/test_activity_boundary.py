"""Trusted interaction registry, launch permits and the automatic-review admission contract."""

from __future__ import annotations

import asyncio
import statistics
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from mordred_hermes.activity import _review_jobs, _review_run, boundary, review
from mordred_hermes.activity.store import ActivityStore
from mordred_hermes.extension import activity_api
from tests._activity_review_helpers import (
    FakeLessons,
    LegacyLlm,
    answer,
    config,
    correction_episode,
    make_store,
    result,
)

LOCAL = "http://127.0.0.1:11434"


class RecordingThread:
    """A thread factory that records instead of starting; ``run()`` executes the target inline."""

    started: ClassVar[list[RecordingThread]] = []

    def __init__(self, *, target: Any, args: tuple[Any, ...], name: str, daemon: bool) -> None:
        self.target, self.args, self.name, self.daemon = target, args, name, daemon

    def start(self) -> None:
        RecordingThread.started.append(self)

    def run(self) -> None:
        self.target(*self.args)


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("mordred_hermes._home.hermes_home", lambda: home)
    monkeypatch.setattr(_review_run, "_policy_mode", lambda: "lenient")
    monkeypatch.setattr(_review_jobs, "write_audit", lambda entry: None)
    monkeypatch.setattr(review, "default_audit_sink", lambda: lambda entry: None)
    boundary._permits.clear()
    boundary._workers.clear()
    RecordingThread.started = []
    return home


@pytest.fixture
def store(tmp_path: Path) -> ActivityStore:
    return make_store(tmp_path)


def _automatic(monkeypatch: pytest.MonkeyPatch, store: ActivityStore, **cfg: Any) -> None:
    settings = config(review_mode="task_boundary", review_provider=LOCAL, review_model="m1", **cfg)
    monkeypatch.setattr(boundary, "_load_config", lambda home: settings)
    monkeypatch.setattr(boundary, "_protected", lambda home: True)
    monkeypatch.setattr(review, "open_review_store", lambda home: store)


def _llm(store: ActivityStore) -> LegacyLlm:
    evidence = [item.event_id for item in store.events_for_episode("ep-corr")]
    return LegacyLlm(result(answer(evidence), provider=LOCAL, model="m1"))


# --------------------------------------------------------------------------- #
# Hooks: observation only
# --------------------------------------------------------------------------- #


def test_hooks_are_fast_with_no_store(isolated: Path) -> None:
    timings: list[float] = []
    for index in range(200):
        start = time.perf_counter()
        boundary.on_session_start(session_id=f"s-{index}", platform="cli")
        boundary.on_session_end(session_id=f"s-{index}", completed=True, interrupted=False, model="m")
        boundary.on_session_finalize(session_id=f"s-{index}", platform="cli", reason="shutdown")
        timings.append((time.perf_counter() - start) / 3)

    p95 = statistics.quantiles(timings, n=20)[18]
    assert p95 < 0.020
    assert not (isolated / "plugin-data").exists()
    assert len(boundary.recent_events()) == 64  # bounded


def test_hooks_record_identifiers_and_tolerate_missing_fields(isolated: Path) -> None:
    boundary.on_session_end(session_id="s-1", interrupted=True)
    boundary.on_session_end()  # 0.19.0 dispatch sites differ; nothing is required beyond session_id
    boundary.on_session_end(session_id="x" * 1000, completed=True)

    kinds = [(sid, kind) for _home, sid, kind, _t in boundary.recent_events()[-3:]]
    assert kinds == [("s-1", "interrupted"), ("", "end"), ("", "completed")]
    assert all(home == str(isolated.resolve()) for home, *_ in boundary.recent_events()[-3:])


def test_hooks_and_manual_mode_never_call_the_model(monkeypatch: pytest.MonkeyPatch, store: ActivityStore) -> None:
    correction_episode(store)
    llm = _llm(store)
    _automatic(monkeypatch, store)
    monkeypatch.setattr(boundary, "_load_config", lambda home: config(review_mode="manual"))

    for index in range(50):
        boundary.on_session_start(session_id=f"s-{index}")
        boundary.on_session_end(session_id=f"s-{index}", completed=True)
        boundary.on_session_finalize(session_id=f"s-{index}")
    boundary.grant_launch_permit(Path("."), "req", time.time())
    started = boundary.try_automatic_review(Path("."), llm=llm, now=time.time(), thread_factory=RecordingThread)

    assert started is False
    assert llm.calls == [] and RecordingThread.started == []
    assert boundary.consume_permit(Path("."), None, time.time()) is not None  # manual mode left it untouched


# --------------------------------------------------------------------------- #
# Permits
# --------------------------------------------------------------------------- #


def test_permit_is_single_use_and_expires(tmp_path: Path) -> None:
    now = 1000.0
    granted = boundary.grant_launch_permit(tmp_path, "req-1", now)

    assert boundary.consume_permit(tmp_path, "other", now) is None
    assert boundary.consume_permit(tmp_path / ".", "req-1", now + 1) == granted  # keyed by realpath
    assert boundary.consume_permit(tmp_path, None, now + 2) is None

    boundary.grant_launch_permit(tmp_path, "req-2", now)
    assert boundary.consume_permit(tmp_path, None, now + boundary.PERMIT_TTL_S + 1) is None


def test_finalize_and_new_input_revoke_unused_permits(isolated: Path) -> None:
    boundary.grant_launch_permit(isolated, "req", time.time())
    boundary.on_session_finalize(session_id="s-1", reason="shutdown")
    assert boundary.consume_permit(isolated, None, time.time()) is None

    boundary.grant_launch_permit(isolated, "req", time.time())
    activity_api.before_foreground_input(None)
    assert boundary.consume_permit(isolated, None, time.time()) is None


def test_a_newer_permit_replaces_the_older_one(tmp_path: Path) -> None:
    boundary.grant_launch_permit(tmp_path, "old", 1.0)
    newer = boundary.grant_launch_permit(tmp_path, "new", 2.0)
    assert boundary.consume_permit(tmp_path, None, 3.0) == newer


# --------------------------------------------------------------------------- #
# Automatic admission
# --------------------------------------------------------------------------- #


def test_automatic_review_needs_a_permit_and_runs_once(
    monkeypatch: pytest.MonkeyPatch, store: ActivityStore, isolated: Path
) -> None:
    FakeLessons().install(monkeypatch)
    correction_episode(store)
    llm = _llm(store)
    _automatic(monkeypatch, store)
    now = time.time()

    assert not boundary.try_automatic_review(isolated, llm=llm, now=now, thread_factory=RecordingThread)
    boundary.grant_launch_permit(isolated, "req", now)
    assert boundary.try_automatic_review(isolated, llm=llm, now=now, thread_factory=RecordingThread)
    assert not boundary.try_automatic_review(isolated, llm=llm, now=now, thread_factory=RecordingThread)  # used

    (thread,) = RecordingThread.started
    assert thread.daemon and llm.calls == []
    # The worker never consults the process home: it runs on what it was given.
    monkeypatch.setattr("mordred_hermes._home.hermes_home", lambda: (_ for _ in ()).throw(AssertionError))
    thread.run()

    assert len(llm.calls) == 1
    assert rows_of(store, "SELECT state FROM activity_review_jobs") == [("completed",)]
    assert rows_of(store, "SELECT count(*) FROM activity_lessons") == [(1,)]


def test_one_worker_per_home(monkeypatch: pytest.MonkeyPatch, store: ActivityStore, isolated: Path) -> None:
    correction_episode(store)
    _automatic(monkeypatch, store)
    now = time.time()

    boundary.grant_launch_permit(isolated, "a", now)
    assert boundary.try_automatic_review(isolated, llm=_llm(store), now=now, thread_factory=RecordingThread)
    boundary.grant_launch_permit(isolated, "b", now)
    assert not boundary.try_automatic_review(isolated, llm=_llm(store), now=now, thread_factory=RecordingThread)


def test_unprotected_store_or_disabled_feature_is_refused(
    monkeypatch: pytest.MonkeyPatch, store: ActivityStore, isolated: Path
) -> None:
    _automatic(monkeypatch, store)
    monkeypatch.setattr(boundary, "_protected", lambda home: False)
    boundary.grant_launch_permit(isolated, "req", time.time())
    assert not boundary.try_automatic_review(isolated, llm=_llm(store), now=time.time(), thread_factory=RecordingThread)

    monkeypatch.setattr(boundary, "_protected", lambda home: True)
    monkeypatch.setattr(boundary, "_load_config", lambda home: config(enabled=False, review_mode="task_boundary"))
    assert not boundary.try_automatic_review(isolated, llm=_llm(store), now=time.time(), thread_factory=RecordingThread)
    assert RecordingThread.started == []


def test_new_input_while_the_worker_waits_prevents_submission(
    monkeypatch: pytest.MonkeyPatch, store: ActivityStore, isolated: Path
) -> None:
    correction_episode(store)
    llm = _llm(store)
    _automatic(monkeypatch, store)
    now = time.time()
    boundary.grant_launch_permit(isolated, "req", now)
    assert boundary.try_automatic_review(isolated, llm=llm, now=now, thread_factory=RecordingThread)

    boundary.revoke_permits(isolated, "foreground_input")
    RecordingThread.started[0].run()

    assert llm.calls == []
    assert rows_of(store, "SELECT state FROM activity_review_jobs") == [("pending",)]


def test_reconcile_enqueues_without_a_model(
    monkeypatch: pytest.MonkeyPatch, store: ActivityStore, isolated: Path
) -> None:
    correction_episode(store)
    _automatic(monkeypatch, store)

    report = boundary.reconcile(isolated, time.time())

    assert [item.signal for item in report.eligible] == ["correction"] and len(report.job_ids) == 1


# --------------------------------------------------------------------------- #
# Registration and the extension consumer
# --------------------------------------------------------------------------- #


class Ctx:
    def __init__(self, *, reject_task: bool = False) -> None:
        self.hooks: list[str] = []
        self.tasks: list[tuple[str, dict[str, Any]]] = []
        self.reject_task = reject_task

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks.append(name)

    def register_auxiliary_task(self, key: str, **kwargs: Any) -> None:
        if self.reject_task:
            raise ValueError("unknown task key")
        self.tasks.append((key, kwargs))


def test_register_hooks_registers_three_hooks_and_the_review_task() -> None:
    ctx = Ctx()
    boundary.register_hooks(ctx)
    assert ctx.hooks == ["on_session_start", "on_session_end", "on_session_finalize"]
    ((key, kwargs),) = ctx.tasks
    assert key == "mordred_activity_review"
    assert kwargs["defaults"] == {"provider": "auto", "model": "", "timeout": 30}


def test_register_hooks_survives_a_rejected_task_and_a_host_without_tasks() -> None:
    rejecting = Ctx(reject_task=True)
    boundary.register_hooks(rejecting)
    assert len(rejecting.hooks) == 3

    plain = SimpleNamespace(hooks=[])
    plain.register_hook = lambda name, callback: plain.hooks.append(name)
    boundary.register_hooks(plain)
    assert len(plain.hooks) == 3


def test_delivery_without_a_host_llm_grants_but_never_reviews(
    monkeypatch: pytest.MonkeyPatch, store: ActivityStore, isolated: Path
) -> None:
    _automatic(monkeypatch, store)
    started: list[Any] = []
    monkeypatch.setattr(boundary, "try_automatic_review", lambda *a, **k: started.append(a) or True)

    admitted = asyncio.run(activity_api.after_foreground_delivery(SimpleNamespace(activity_llm=None), "req-1"))

    assert admitted is False and started == []
    assert boundary.consume_permit(isolated, "req-1", time.time()) is not None


def test_delivery_with_a_host_llm_considers_one_review(
    monkeypatch: pytest.MonkeyPatch, store: ActivityStore, isolated: Path
) -> None:
    correction_episode(store)
    _automatic(monkeypatch, store)
    calls: list[dict[str, Any]] = []

    def fake_try(home: Any, *, llm: Any, now: float) -> bool:
        calls.append({"home": home, "llm": llm, "permit": boundary.consume_permit(home, None, now)})
        return True

    monkeypatch.setattr(boundary, "try_automatic_review", fake_try)
    llm = _llm(store)
    admitted = asyncio.run(activity_api.after_foreground_delivery(SimpleNamespace(activity_llm=llm), "req-2"))

    assert admitted is True
    assert calls[0]["llm"] is llm and calls[0]["permit"].session_id == "req-2"


def rows_of(store: ActivityStore, sql: str) -> list[tuple[Any, ...]]:
    with store.connection() as conn:
        return [tuple(row) for row in conn.execute(sql)]
