"""Owned Desktop jobs and bounded in-memory terminal results.

Admission and finalization run on the Desktop event loop. Blocking operations
remain owned through cancellation: callers must interpret their actual result
before a job becomes terminal and releases its exclusion slot.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import functools
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, ParamSpec, TypeVar

_log = logging.getLogger(__name__)
_P = ParamSpec("_P")
_T = TypeVar("_T")


class JobBusy(RuntimeError):
    def __init__(self, kind: str) -> None:
        self.code = f"{kind}_busy"
        super().__init__(self.code)


@dataclass
class Job:
    job_id: str
    kind: str
    state: Literal["running", "done", "failed"] = "running"
    error: str | None = None
    progress: dict[str, Any] = field(default_factory=dict)
    completed: float | None = None
    _task: asyncio.Task[None] | None = field(default=None, repr=False)
    _future: asyncio.Future[Any] | None = field(default=None, repr=False)

    async def run_sync(self, work: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs) -> _T:
        """Run blocking work with caller context; drain cancellation until it ends."""
        context = contextvars.copy_context()
        future = asyncio.get_running_loop().run_in_executor(None, context.run, functools.partial(work, *args, **kwargs))
        self._future = future
        try:
            while True:
                try:
                    return await asyncio.shield(future)
                except asyncio.CancelledError:
                    # A completed callable can itself raise CancelledError. Retrieve
                    # that outcome exactly once instead of retrying it forever.
                    if future.done():
                        return future.result()
        finally:
            self._future = None


JobWork = Callable[[Job], Awaitable[None]]


class JobRegistry:
    def __init__(
        self,
        *,
        emit: Callable[[str, dict[str, Any]], None],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._emit = emit
        self._clock = clock
        self._jobs: dict[str, Job] = {}

    def prune(self) -> None:
        now = self._clock()
        terminal = sorted(
            (job for job in self._jobs.values() if job.completed is not None),
            key=lambda job: job.completed if job.completed is not None else 0.0,
        )
        for index, job in enumerate(terminal):
            assert job.completed is not None
            if now - job.completed >= 3600 or index < len(terminal) - 64:
                del self._jobs[job.job_id]

    def get(self, job_id: str) -> Job | None:
        self.prune()
        return self._jobs.get(job_id)

    def running(self) -> list[Job]:
        self.prune()
        return [job for job in self._jobs.values() if job.state == "running"]

    def is_running(self, kind: str) -> bool:
        return any(job.kind == kind for job in self.running())

    def start(self, kind: str, work: JobWork) -> Job:
        active = self.running()
        for job in active:
            if job.kind == kind:
                return job
        conflict = {"update": "uninstall", "uninstall": "update"}.get(kind)
        if any(job.kind == conflict for job in active):
            raise JobBusy(kind)
        job = Job(secrets.token_urlsafe(12), kind)

        async def run() -> None:
            await work(job)

        task = asyncio.get_running_loop().create_task(run())
        job._task = task
        self._jobs[job.job_id] = job
        # A coroutine's finally block cannot handle cancellation before its
        # first execution. The Task callback owns every finalization path.
        task.add_done_callback(functools.partial(self._finish, job))
        return job

    def _finish(self, job: Job, task: asyncio.Task[None]) -> None:
        error = asyncio.CancelledError() if task.cancelled() else task.exception()
        if error is None:
            job.state = "done"
        else:
            code = getattr(error, "code", None)
            job.state = "failed"
            job.error = code if isinstance(code, str) and code else f"{job.kind}_failed"
            _log.warning("mordred desktop job %s failed (%s)", job.kind, type(error).__name__)
        job.completed = self._clock()
        job._task = None
        self.prune()
        with contextlib.suppress(Exception):
            self._emit("job", {"job_id": job.job_id, "kind": job.kind, "state": job.state, "error": job.error})
