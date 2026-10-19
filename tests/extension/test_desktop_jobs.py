"""Desktop job ownership, admission and bounded result retention."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import functools
import threading

import pytest

from mordred_hermes.desktop import api


def async_test(work):
    @functools.wraps(work)
    def run(*args, **kwargs):
        return asyncio.run(work(*args, **kwargs))

    return run


async def checkpoint():
    reached = asyncio.Event()
    asyncio.get_running_loop().call_soon(reached.set)
    await reached.wait()


@async_test
async def test_pre_start_cancellation_finalizes_job(registry):
    _, events = registry

    async def work(job):
        pytest.fail("cancelled before first execution")

    before = asyncio.all_tasks()
    job = api._start_job("prestart", work)
    task = (asyncio.all_tasks() - before).pop()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    await checkpoint()
    assert job.state == "failed"
    assert job.error == "prestart_failed"
    assert job._task is None and job._future is None
    assert events == [
        ("job", {"job_id": job.job_id, "kind": "prestart", "state": "failed", "error": "prestart_failed"})
    ]


@pytest.fixture
def registry(monkeypatch):
    from mordred_hermes.desktop._jobs import JobRegistry

    events = []
    instance = JobRegistry(emit=lambda event, payload: events.append((event, payload)))
    monkeypatch.setattr(api, "_JOBS", instance)
    return instance, events


async def finish(job):
    task = job._task
    assert task is not None
    with contextlib.suppress(Exception, asyncio.CancelledError):
        await task
    await checkpoint()
    assert job._task is None
    assert job._future is None


async def succeed(job):
    job.progress = {"answer": 42}


@async_test
@pytest.mark.parametrize("outcome", ["success", "coded", "generic", "cancelled"])
async def test_blocking_work_drains_repeated_cancellation_and_preserves_result(registry, outcome):
    from mordred_hermes.desktop._jobs import JobBusy

    jobs, events = registry
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    value = contextvars.ContextVar("job_context")
    value.set("caller context")
    observed = []

    def blocking():
        observed.append(value.get())
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(5), "test must release worker"
        if outcome == "coded":
            raise api._Fail("worker_refused")
        if outcome == "generic":
            raise RuntimeError("do not expose")
        if outcome == "cancelled":
            raise asyncio.CancelledError()
        return 42

    async def work(job):
        job.progress = {"answer": await job.run_sync(blocking)}

    job = jobs.start("update", work)
    try:
        await asyncio.wait_for(entered.wait(), 5)
        task, future = job._task, job._future
        assert task is not None and future is not None
        for _ in range(3):
            task.cancel()
            await checkpoint()
            assert not task.done()
            assert job.state == "running" and jobs.is_running("update")
            assert jobs.start("update", succeed) is job
            with pytest.raises(JobBusy) as exc:
                jobs.start("uninstall", succeed)
            assert exc.value.code == "uninstall_busy"
            assert job._future is future and not future.cancelled()
            assert events == []
    finally:
        release.set()
    await asyncio.wait_for(finish(job), 5)
    assert observed == ["caller context"]
    assert job.state == ("done" if outcome == "success" else "failed")
    assert (
        job.error
        == {"success": None, "coded": "worker_refused", "generic": "update_failed", "cancelled": "update_failed"}[
            outcome
        ]
    )
    assert job.progress == ({"answer": 42} if outcome == "success" else {})
    assert len(events) == 1
    assert not jobs.is_running("update")
    await finish(jobs.start("uninstall", succeed))


@async_test
async def test_async_cancellation_without_worker_fails_and_releases(registry):
    jobs, events = registry
    entered = asyncio.Event()
    parked = asyncio.Event()

    async def work(job):
        entered.set()
        await parked.wait()

    job = jobs.start("hardware", work)
    await entered.wait()
    job._task.cancel()
    await finish(job)
    assert (job.state, job.error) == ("failed", "hardware_failed")
    assert len(events) == 1


@async_test
@pytest.mark.parametrize("first,second", [("update", "uninstall"), ("uninstall", "update")])
async def test_admission_is_synchronous_and_hardware_independent(registry, first, second):
    from mordred_hermes.desktop._jobs import JobBusy

    jobs, _ = registry
    job = jobs.start(first, succeed)
    assert jobs.start(first, succeed) is job
    with pytest.raises(JobBusy) as exc:
        jobs.start(second, succeed)
    assert exc.value.code == second + "_busy"
    hardware = jobs.start("hardware", succeed)
    enclave = jobs.start("enclave", succeed)
    assert jobs.running() == [job, hardware, enclave]
    for item in (job, hardware, enclave):
        if item._task is not None:
            await finish(item)
    assert jobs.running() == []


@async_test
async def test_retention_uses_completion_age_and_exact_ttl_boundary():
    from mordred_hermes.desktop._jobs import JobRegistry

    now = [0.0]
    jobs = JobRegistry(emit=lambda *_: None, clock=lambda: now[0])
    release = asyncio.Event()

    async def work(job):
        await release.wait()

    job = jobs.start("hardware", work)
    now[0] = 10_000.0
    assert jobs.get(job.job_id) is job
    release.set()
    await finish(job)
    now[0] = 13_599.999
    assert jobs.get(job.job_id) is job
    now[0] = 13_600.0
    assert jobs.get(job.job_id) is None


@async_test
async def test_terminal_limit_uses_completion_order_then_insertion_and_keeps_active():
    from mordred_hermes.desktop._jobs import JobRegistry

    jobs = JobRegistry(emit=lambda *_: None, clock=lambda: 0.0)
    release = asyncio.Event()

    async def work(job):
        await release.wait()

    active = jobs.start("active", work)
    oldest_inserted = jobs.start("oldest", work)
    completed = []
    for n in range(64):
        job = jobs.start(str(n), succeed)
        await finish(job)
        completed.append(job)
    assert jobs.get(active.job_id) is active
    assert jobs.get(completed[0].job_id) is completed[0]
    release.set()
    await finish(oldest_inserted)
    await checkpoint()
    # All completions tie: insertion order evicts both early active jobs.
    assert jobs.get(oldest_inserted.job_id) is None
    assert jobs.get(active.job_id) is None
    assert all(jobs.get(job.job_id) is job for job in completed)
    newer = jobs.start("newer", succeed)
    await finish(newer)
    assert jobs.get(completed[0].job_id) is None
    assert jobs.get(completed[1].job_id) is completed[1]


@async_test
@pytest.mark.parametrize("trigger", ["start", "lookup", "status", "completion"])
async def test_prunes_expired_results_at_each_boundary(trigger):
    from mordred_hermes.desktop._jobs import JobRegistry

    now = [0.0]
    jobs = JobRegistry(emit=lambda *_: None, clock=lambda: now[0])
    expired = jobs.start("expired", succeed)
    await finish(expired)
    pending = jobs.start("pending", succeed)
    now[0] = 3600.0
    if trigger == "start":
        other = jobs.start("other", succeed)
        await finish(other)
    elif trigger == "lookup":
        jobs.get("missing")
    elif trigger == "status":
        jobs.running()
    else:
        await finish(pending)
    # Inspect storage without causing another prune.
    assert expired.job_id not in jobs._jobs
    if pending._task is not None:
        await finish(pending)


@async_test
async def test_event_failure_does_not_retain_resources_or_running_state():
    from mordred_hermes.desktop._jobs import JobRegistry

    def emit(*args):
        raise RuntimeError("unavailable event transport")

    jobs = JobRegistry(emit=emit)
    job = jobs.start("hardware", succeed)
    await finish(job)
    assert job.state == "done" and not jobs.is_running("hardware")


@async_test
@pytest.mark.parametrize("kind", ["hardware", "enclave", "update", "uninstall"])
@pytest.mark.parametrize("failed", [False, True])
async def test_real_api_callback_keeps_outcome_and_progress_after_cancellation(
    registry, monkeypatch, tmp_path, kind, failed
):
    from types import SimpleNamespace

    from mordred_hermes import _self_update as core
    from mordred_hermes.wizard import keyvault_native_cli, uninstall_cli

    jobs, events = registry
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    calls = []
    monkeypatch.setattr(api, "_emit", lambda *_: None)
    monkeypatch.setattr(api, "_home", lambda: tmp_path)
    monkeypatch.setattr(api, "_uninstall_context", lambda prompt: object())
    monkeypatch.setattr(api, "_prepare_update", lambda target: (object(), tmp_path / "uv"))
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux" if kind == "hardware" else "darwin"))

    def blocking(*args, **kwargs):
        calls.append(kind)
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(5), "test must release worker"
        if kind == "update":
            if failed:
                raise core.UpdateFailed(
                    "install-package", "controlled failure", rolled_back=False, rollback_output="rb"
                )
            return core.UpdateReport("0.2.0a1", "0.2.0a3", ())
        if kind == "uninstall":
            print("Uninstall summary")
        return int(failed)

    monkeypatch.setattr(keyvault_native_cli, "enable_tpm", blocking)
    monkeypatch.setattr(keyvault_native_cli, "enable_se", blocking)
    monkeypatch.setattr(core, "apply", blocking)
    monkeypatch.setattr(uninstall_cli, "run_uninstall", blocking)

    async def start():
        if kind == "hardware":
            return await api.hardware_build()
        if kind == "enclave":
            return await api.enclave_build()
        if kind == "update":
            return await api.update_apply({"version": "0.2.0a3"})
        return await api.uninstall({})

    result = await start()
    job = jobs.get(result["job_id"])
    assert set(result) == {"ok", "job_id", "kind", "state", "error", "progress"}
    try:
        await asyncio.wait_for(entered.wait(), 5)
        for _ in range(2):
            job._task.cancel()
            await checkpoint()
            assert (await api.job_status(job.job_id))["state"] == "running"
            assert (await start())["job_id"] == job.job_id
        assert calls == [kind]
    finally:
        release.set()
    await finish(job)
    assert job.state == ("failed" if failed else "done")
    assert job.error == (
        None
        if not failed
        else {
            "hardware": "tpm_build_failed",
            "enclave": "enclave_build_failed",
            "update": "update_rollback_failed",
            "uninstall": "uninstall_failed",
        }[kind]
    )
    assert len(events) == 1
    if kind == "uninstall":
        assert job.progress == {"summary": "Uninstall summary\n"}
    elif kind == "update":
        if failed:
            assert job.progress == {
                "target": "0.2.0a3",
                "step": "install-package",
                "output": "controlled failure",
                "rolled_back": False,
                "rollback_output": "rb",
            }
        else:
            assert job.progress["report"]["target"] == "0.2.0a3"


@async_test
async def test_update_checks_uninstall_started_during_preflight(registry, monkeypatch):
    import json

    jobs, _ = registry
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    parked = asyncio.Event()

    def prepare(target):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(5)
        return object(), object()

    async def work(job):
        await parked.wait()

    monkeypatch.setattr(api, "_prepare_update", prepare)
    request = asyncio.create_task(api.update_apply({"version": "0.2.0a3"}))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        uninstall = jobs.start("uninstall", work)
    finally:
        release.set()
    result = await request
    assert result.status_code == 200
    assert json.loads(result.body) == {"ok": False, "error": "update_busy"}
    assert jobs.running() == [uninstall]
    parked.set()
    await finish(uninstall)


@async_test
@pytest.mark.parametrize("kind,conflict", [("update", "uninstall"), ("uninstall", "update")])
async def test_final_admission_conflict_keeps_http_error_and_confirmation_order(registry, monkeypatch, kind, conflict):
    import json

    jobs, _ = registry
    parked = asyncio.Event()

    async def work(job):
        await parked.wait()

    active = jobs.start(conflict, work)
    monkeypatch.setattr(api, "_running", lambda kind: False)
    monkeypatch.setattr(api, "_prepare_update", lambda target: (object(), object()))
    try:
        if kind == "update":
            result = await api.update_apply({"version": "0.2.0a3"})
        else:
            invalid = await api.uninstall({"purge_data": True})
            assert json.loads(invalid.body)["error"] == "uninstall_confirm_mismatch"
            result = await api.uninstall({})
        assert result.status_code == 200
        assert json.loads(result.body) == {"ok": False, "error": kind + "_busy"}
    finally:
        parked.set()
        await finish(active)


@async_test
async def test_status_prunes_and_missing_expired_evicted_results_keep_wire_error(monkeypatch):
    import json
    from types import SimpleNamespace

    from mordred_hermes.desktop._jobs import JobRegistry

    now = [0.0]
    jobs = JobRegistry(emit=lambda *_: None, clock=lambda: now[0])
    monkeypatch.setattr(api, "_JOBS", jobs)
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="unsupported"))
    expired = jobs.start("expired", succeed)
    await finish(expired)
    now[0] = 3600.0
    assert (await api.status())["jobs"] == []
    assert expired.job_id not in jobs._jobs
    for n in range(65):
        job = jobs.start(str(n), succeed)
        if n == 0:
            evicted = job
        await finish(job)
    for job_id in ("missing", expired.job_id, evicted.job_id):
        result = await api.job_status(job_id)
        assert result.status_code == 200
        assert json.loads(result.body) == {"ok": False, "error": "job_not_found"}


@async_test
async def test_completion_order_precedes_insertion_order_for_eviction():
    from mordred_hermes.desktop._jobs import JobRegistry

    now = [0.0]
    jobs = JobRegistry(emit=lambda *_: None, clock=lambda: now[0])
    release = asyncio.Event()

    async def long_work(job):
        await release.wait()

    first_started = jobs.start("long", long_work)
    first_completed = jobs.start("quick", succeed)
    await finish(first_completed)
    now[0] = 1.0
    release.set()
    await finish(first_started)
    for n in range(63):
        await finish(jobs.start(str(n), succeed))
    assert jobs.get(first_completed.job_id) is None
    assert jobs.get(first_started.job_id) is first_started


@async_test
@pytest.mark.parametrize("failed", [False, True])
async def test_cancellation_at_completed_worker_preserves_result(registry, failed):
    jobs, events = registry
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()

    def blocking():
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(5)
        if failed:
            raise api._Fail("worker_error")
        return 7

    async def work(job):
        job.progress = {"answer": await job.run_sync(blocking)}

    job = jobs.start("hardware", work)
    try:
        await asyncio.wait_for(entered.wait(), 5)
        task = job._task
        job._future.add_done_callback(lambda future: task.cancel())
    finally:
        release.set()
    await finish(job)
    assert (job.state, job.error) == (("failed", "worker_error") if failed else ("done", None))
    assert job.progress == ({} if failed else {"answer": 7})
    assert len(events) == 1
