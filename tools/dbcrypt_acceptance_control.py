#!/usr/bin/env python3
"""Bounded, task-owned EC2 acceptance runs with an independent supervisor.

This operator tool never receives account passwords or writes AWS credentials.
Only the two retained database validation instances are admitted. A private
receipt and matching EC2 tag identify a run; neither authorizes taking over
another task's running instance.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

INSTANCES = frozenset({"i-00f4db5c3a204906b", "i-095cbe655c196c749"})
PROFILE = "intmax-dev"
REGION = "ap-southeast-1"
OWNER_TAG = "mordred:dbcrypt-validation"
STOP_MARGIN = 60.0


class ControlRefused(RuntimeError):
    """An actionable, non-secret reason why compute was not touched."""


class Cloud(Protocol):
    def identity(self) -> str: ...
    def credential_expiration(self) -> float | None: ...
    def observe(self, instance: str) -> tuple[str, str | None]: ...
    def claim(self, instance: str, owner: str) -> None: ...
    def start(self, instance: str) -> None: ...
    def stop(self, instance: str) -> None: ...
    def release(self, instance: str, owner: str) -> None: ...


class AwsCli:
    def __init__(self, profile: str = PROFILE, region: str = REGION) -> None:
        if (profile, region) != (PROFILE, REGION):
            raise ControlRefused("unapproved_profile_or_region")
        executable = shutil.which("aws")
        if executable is None:
            raise ControlRefused("aws_cli_unavailable")
        self.command = [executable, "--profile", profile, "--region", region, "--no-cli-pager"]

    def _call(self, *args: str) -> Any:
        try:
            result = subprocess.run(
                [*self.command, *args],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
                env={**os.environ, "AWS_PAGER": "", "AWS_CLI_AUTO_PROMPT": "off"},
            )
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            # stdout may contain exported credentials: never include it in an error.
            raise ControlRefused("aws_request_failed") from exc

    def identity(self) -> str:
        value = self._call("sts", "get-caller-identity").get("Account")
        if not isinstance(value, str) or len(value) != 12 or not value.isdecimal():
            raise ControlRefused("aws_identity_unknown")
        return value

    def credential_expiration(self) -> float | None:
        credentials = self._call("configure", "export-credentials", "--format", "process")
        expiration = credentials.get("Expiration")
        if expiration:
            return datetime.fromisoformat(str(expiration).replace("Z", "+00:00")).timestamp()
        if credentials.get("SessionToken") or not credentials.get("AccessKeyId"):
            raise ControlRefused("credential_expiration_unknown")
        return None  # Static IAM credentials have no session expiration.

    def observe(self, instance: str) -> tuple[str, str | None]:
        payload = self._call("ec2", "describe-instances", "--instance-ids", instance)
        rows = [i for r in payload.get("Reservations", []) for i in r.get("Instances", [])]
        if len(rows) != 1 or rows[0].get("InstanceId") != instance:
            raise ControlRefused("instance_identity_unknown")
        owners = [t["Value"] for t in rows[0].get("Tags", []) if t.get("Key") == OWNER_TAG]
        if len(owners) > 1:
            raise ControlRefused("instance_owner_unknown")
        return str(rows[0]["State"]["Name"]), owners[0] if owners else None

    def claim(self, instance: str, owner: str) -> None:
        self._call("ec2", "create-tags", "--resources", instance, "--tags", f"Key={OWNER_TAG},Value={owner}")

    def start(self, instance: str) -> None:
        self._call("ec2", "start-instances", "--instance-ids", instance)

    def stop(self, instance: str) -> None:
        self._call("ec2", "stop-instances", "--instance-ids", instance)

    def release(self, instance: str, owner: str) -> None:
        self._call("ec2", "delete-tags", "--resources", instance, "--tags", f"Key={OWNER_TAG},Value={owner}")


def _check_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ControlRefused("unsafe_receipt")
    if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ControlRefused("unsafe_receipt_permissions")


@contextlib.contextmanager
def _receipt_lock(path: Path) -> Iterator[None]:
    if not path.is_absolute():
        path = path.absolute()
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or (os.name != "nt" and parent.st_mode & 0o022):
        raise ControlRefused("unsafe_receipt_parent")
    lock = path.with_name(path.name + ".lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        _check_file(lock)
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"0")
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if sys.platform == "win32":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _write(path: Path, value: dict[str, Any], *, create: bool = False) -> None:
    data = (json.dumps(value, sort_keys=True) + "\n").encode()
    if create:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return
    _check_file(path)
    fd, temporary = tempfile.mkstemp(prefix=".dbcrypt-receipt-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes as c
        from ctypes import wintypes as w

        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
        kernel.OpenProcess.restype = w.HANDLE
        kernel.GetExitCodeProcess.argtypes = (w.HANDLE, c.POINTER(w.DWORD))
        kernel.GetExitCodeProcess.restype = w.BOOL
        kernel.CloseHandle.argtypes = (w.HANDLE,)
        kernel.CloseHandle.restype = w.BOOL
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = w.DWORD()
            return bool(kernel.GetExitCodeProcess(handle, c.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class Controller:
    def __init__(
        self,
        cloud: Cloud,
        *,
        now: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cloud, self.now, self.sleep = cloud, now, sleep

    def _read(self, path: Path) -> dict[str, Any]:
        _check_file(path)
        value = json.loads(path.read_text())
        if (
            not isinstance(value, dict)
            or value.get("version") != 1
            or value.get("instance") not in INSTANCES
            or not isinstance(value.get("run"), str)
            or len(value["run"]) != 32
            or not isinstance(value.get("created"), (int, float))
            or not isinstance(value.get("deadline"), (int, float))
            or not 120 <= value["deadline"] - value["created"] <= 7200
        ):
            raise ControlRefused("invalid_receipt")
        return value

    def read(self, path: Path) -> dict[str, Any]:
        with _receipt_lock(path):
            return self._read(path)

    def arm(self, path: Path, *, instance: str, deadline: float) -> dict[str, Any]:
        now = self.now()
        if instance not in INSTANCES:
            raise ControlRefused("unapproved_instance")
        if not math.isfinite(deadline) or not 120 <= deadline - now <= 7200:
            raise ControlRefused("invalid_deadline")
        expiration = self.cloud.credential_expiration()
        if expiration is not None and expiration <= deadline + 120:
            raise ControlRefused("credential_expires_before_cleanup")
        account = self.cloud.identity()
        state, owner = self.cloud.observe(instance)
        if state != "stopped" or owner is not None:
            raise ControlRefused("instance_already_owned_or_running")
        value = dict(
            version=1,
            instance=instance,
            run=uuid.uuid4().hex,
            account=account,
            created=now,
            deadline=deadline,
            state="armed",
            start_requested=False,
            supervisor_pid=None,
            heartbeat=None,
        )
        with _receipt_lock(path):
            if path.exists() or path.is_symlink():
                raise ControlRefused("receipt_already_exists")
            _write(path, value, create=True)
        return value

    def record_heartbeat(self, path: Path, *, pid: int) -> None:
        with _receipt_lock(path):
            value = self._read(path)
            value.update(supervisor_pid=pid, heartbeat=self.now())
            _write(path, value)

    def start(self, path: Path) -> dict[str, Any]:
        with _receipt_lock(path):
            value = self._read(path)
            heartbeat, pid = value.get("heartbeat"), value.get("supervisor_pid")
            if (
                not isinstance(heartbeat, (int, float))
                or self.now() - heartbeat > 10
                or not isinstance(pid, int)
                or not _alive(pid)
            ):
                raise ControlRefused("supervisor_not_live")
            if value["state"] != "armed" or self.now() >= value["deadline"] - STOP_MARGIN:
                raise ControlRefused("deadline_or_state_refuses_start")
            if self.cloud.identity() != value["account"]:
                raise ControlRefused("aws_account_changed")
            if self.cloud.observe(value["instance"]) != ("stopped", None):
                raise ControlRefused("instance_already_owned_or_running")
            self.cloud.claim(value["instance"], value["run"])
            if self.cloud.observe(value["instance"]) != ("stopped", value["run"]):
                raise ControlRefused("instance_owner_changed")
            value.update(start_requested=True, state="start_intent")
            _write(path, value)  # Durable before the possibly ambiguous start RPC.
            if self.now() >= value["deadline"] - STOP_MARGIN:
                value["state"] = "stopping"
                _write(path, value)
                raise ControlRefused("deadline_refuses_start_after_admission")
            # The bounded RPC remains inside the receipt lock: the supervisor
            # cannot release ownership and exit before an in-flight start lands.
            self.cloud.start(value["instance"])
            value["state"] = "running"
            _write(path, value)
        return value

    def stop(self, path: Path) -> dict[str, Any]:
        with _receipt_lock(path):
            value = self._read(path)
            state, owner = self.cloud.observe(value["instance"])
            if not value["start_requested"]:
                if state != "stopped" or owner is not None:
                    raise ControlRefused("instance_owner_changed")
            elif owner != value["run"]:
                if value["state"] == "stopped" and state == "stopped" and owner is None:
                    return value
                raise ControlRefused("instance_owner_changed")
            if state != "stopped":
                value["state"] = "stopping"
                _write(path, value)
                if state != "stopping":
                    self.cloud.stop(value["instance"])
                state, owner = self.cloud.observe(value["instance"])
            if state == "stopped":
                if owner == value["run"]:
                    self.cloud.release(value["instance"], value["run"])
                value.update(state="stopped", stopped_at=self.now())
                _write(path, value)
            return value

    def watch(self, path: Path) -> None:
        while True:
            self.record_heartbeat(path, pid=os.getpid())
            value = self.read(path)
            if value["state"] == "stopped":
                return
            if self.now() >= value["deadline"] - STOP_MARGIN or value["state"] == "stopping":
                try:
                    if self.stop(path)["state"] == "stopped":
                        return
                except (ControlRefused, OSError, TimeoutError) as exc:
                    with _receipt_lock(path):
                        value = self._read(path)
                        value["last_error"] = type(exc).__name__
                        _write(path, value)
            self.sleep(2)


def _launch_supervisor(path: Path) -> int:
    # Freeze the standalone guard outside tracked source before detaching it.
    guard = path.with_suffix(".supervisor.py")
    fd = os.open(guard, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as source:
        source.write(Path(__file__).read_bytes())
        source.flush()
        os.fsync(source.fileno())
    log = path.with_suffix(".supervisor.log")
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        process = subprocess.Popen(
            [sys.executable, str(guard.absolute()), "watch", "--evidence", str(path.absolute())],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    return process.pid


def _arm_supervised(control: Controller, path: Path, args: argparse.Namespace) -> None:
    if not args.instance or not args.deadline_utc:
        raise ControlRefused("arm_requires_instance_and_deadline")
    date = datetime.fromisoformat(args.deadline_utc.replace("Z", "+00:00"))
    if date.tzinfo is None:
        raise ControlRefused("deadline_requires_timezone")
    control.arm(path, instance=args.instance, deadline=date.timestamp())
    pid = _launch_supervisor(path)
    for _ in range(100):
        value = control.read(path)
        if value["supervisor_pid"] == pid and value["heartbeat"] is not None and _alive(pid):
            return
        time.sleep(0.1)
    raise ControlRefused("supervisor_not_ready")


def _stop_verified(control: Controller, path: Path) -> None:
    for _ in range(150):
        if control.stop(path)["state"] == "stopped":
            return
        time.sleep(2)
    raise ControlRefused("stop_not_yet_verified")


def _dispatch(control: Controller, path: Path, args: argparse.Namespace) -> None:
    if args.command == "arm":
        _arm_supervised(control, path, args)
        return
    value = control.read(path)
    if args.instance and value["instance"] != args.instance:
        raise ControlRefused("receipt_instance_mismatch")
    if args.command == "watch":
        control.watch(path)
    elif args.command == "start":
        control.start(path)
    elif args.command == "stop":
        _stop_verified(control, path)
    elif value["state"] != "stopped" or control.cloud.observe(value["instance"])[0] != "stopped":
        raise ControlRefused("stop_not_verified")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("arm", "start", "stop", "verify", "watch"))
    parser.add_argument("--instance", choices=sorted(INSTANCES))
    parser.add_argument("--profile", default=PROFILE, choices=(PROFILE,))
    parser.add_argument("--region", default=REGION, choices=(REGION,))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--deadline-utc")
    args = parser.parse_args(argv)
    try:
        control = Controller(AwsCli(args.profile, args.region))
        path = args.evidence.absolute()  # Do not erase a receipt symlink before admission.
        _dispatch(control, path, args)
        if args.command != "watch":
            value = control.read(path)
            print(json.dumps({k: value[k] for k in ("instance", "run", "state", "deadline", "supervisor_pid")}))
        return 0
    except (ControlRefused, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc) if isinstance(exc, ControlRefused) else type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
