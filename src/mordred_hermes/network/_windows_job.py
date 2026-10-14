"""Kill-on-close Windows job objects for Mordred-launched route daemons.

Standard library only (``ctypes`` over ``kernel32``). A route daemon is
assigned to a fresh, non-inheritable job whose only limit is
``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``. The parent keeps the sole job handle;
when the parent exits for any reason (normal exit, crash, ``TerminateProcess``)
the kernel closes that handle and terminates every process still in the job.
Closing the handle at teardown has the same effect, bounded to exact job
membership: no process is ever selected by image name.

Membership is verified with ``IsProcessInJob`` after assignment. Nested jobs
(Windows 8 and later) let this work when the parent itself already runs inside
a job, for example a terminal or CI runner. The DLL is bound on first native
use only, so importing this module is safe on every platform.
"""

from __future__ import annotations

import ctypes as c
import os
from typing import Any, Final, Protocol

__all__ = ["JobHandle", "KillOnCloseJob"]

DWORD = c.c_uint32
BOOL = c.c_int32
HANDLE = c.c_void_p

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final[int] = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final[int] = 0x2000
PROCESS_TERMINATE: Final[int] = 0x0001
PROCESS_SET_QUOTA: Final[int] = 0x0100
PROCESS_QUERY_LIMITED_INFORMATION: Final[int] = 0x1000


class JobHandle(Protocol):
    """What the Tor lifecycle needs from a job (tests inject fakes)."""

    def assign(self, pid: int) -> None: ...

    def close(self) -> None: ...


class _BasicLimit(c.Structure):
    _fields_ = [
        ("per_process_user_time_limit", c.c_int64),
        ("per_job_user_time_limit", c.c_int64),
        ("limit_flags", DWORD),
        ("minimum_working_set_size", c.c_size_t),
        ("maximum_working_set_size", c.c_size_t),
        ("active_process_limit", DWORD),
        ("affinity", c.c_size_t),
        ("priority_class", DWORD),
        ("scheduling_class", DWORD),
    ]


class _IoCounters(c.Structure):
    _fields_ = [
        ("read_operation_count", c.c_uint64),
        ("write_operation_count", c.c_uint64),
        ("other_operation_count", c.c_uint64),
        ("read_transfer_count", c.c_uint64),
        ("write_transfer_count", c.c_uint64),
        ("other_transfer_count", c.c_uint64),
    ]


class _ExtendedLimit(c.Structure):
    _fields_ = [
        ("basic", _BasicLimit),
        ("io", _IoCounters),
        ("process_memory_limit", c.c_size_t),
        ("job_memory_limit", c.c_size_t),
        ("peak_process_memory_used", c.c_size_t),
        ("peak_job_memory_used", c.c_size_t),
    ]


def _kernel32() -> Any:
    if os.name != "nt":
        raise OSError("Windows job objects are only available on native Windows")
    dll = c.WinDLL  # type: ignore[attr-defined]  # Win32-only ctypes exports
    kernel = dll("kernel32", use_last_error=True)
    bindings: tuple[tuple[str, list[Any], Any], ...] = (
        ("CreateJobObjectW", [c.c_void_p, c.c_wchar_p], HANDLE),
        ("SetInformationJobObject", [HANDLE, c.c_int, c.c_void_p, DWORD], BOOL),
        ("OpenProcess", [DWORD, BOOL, DWORD], HANDLE),
        ("AssignProcessToJobObject", [HANDLE, HANDLE], BOOL),
        ("IsProcessInJob", [HANDLE, HANDLE, c.POINTER(BOOL)], BOOL),
        ("CloseHandle", [HANDLE], BOOL),
    )
    for name, arguments, result in bindings:
        function = getattr(kernel, name)
        function.argtypes = arguments
        function.restype = result
    return kernel


def _failure(operation: str) -> OSError:
    code = int(c.get_last_error())  # type: ignore[attr-defined]
    return OSError(code, f"{operation} failed (Windows error {code})")


class KillOnCloseJob:
    """One kill-on-close job owned by this process."""

    def __init__(self) -> None:
        self._kernel = _kernel32()
        handle = self._kernel.CreateJobObjectW(None, None)
        if not handle:
            raise _failure("CreateJobObjectW")
        self._handle: int | None = handle
        try:
            limits = _ExtendedLimit()
            limits.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self._kernel.SetInformationJobObject(
                handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, c.byref(limits), c.sizeof(limits)
            ):
                raise _failure("SetInformationJobObject")
        except BaseException:
            self.close()
            raise

    def assign(self, pid: int) -> None:
        """Assign ``pid`` and verify membership.

        The caller still holds the ``Popen`` handle of ``pid``, so the process
        object (and therefore the PID) cannot be recycled meanwhile.
        """
        job = self._handle
        if job is None:
            raise OSError("job object is closed")
        access = PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
        process = self._kernel.OpenProcess(access, False, pid)
        if not process:
            raise _failure("OpenProcess")
        try:
            if not self._kernel.AssignProcessToJobObject(job, process):
                raise _failure("AssignProcessToJobObject")
            member = BOOL(0)
            if not self._kernel.IsProcessInJob(process, job, c.byref(member)):
                raise _failure("IsProcessInJob")
            if not member.value:
                raise OSError("process is not a member of its kill-on-close job")
        finally:
            self._kernel.CloseHandle(process)

    def close(self) -> None:
        """Close the only job handle; the kernel terminates remaining members."""
        handle, self._handle = self._handle, None
        if handle is not None and not self._kernel.CloseHandle(handle):
            raise _failure("CloseHandle(job)")
