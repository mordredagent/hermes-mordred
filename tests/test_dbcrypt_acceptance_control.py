"""An independent deadline stops only task-owned AWS compute."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests._dbcrypt_support import AcceptanceClock, SyntheticCloud, acceptance_tool, fake_aws_executable

INSTANCE = "i-00f4db5c3a204906b"


def controller(admission_directory: Path):
    module = acceptance_tool("dbcrypt_acceptance_control")
    clock = AcceptanceClock()
    cloud = SyntheticCloud(clock)
    control = module.Controller(cloud, now=clock.now, sleep=clock.sleep)
    control.admission_directory = admission_directory
    return module, clock, cloud, control


def test_start_requires_live_supervisor_and_private_receipt(tmp_path: Path) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    with pytest.raises(module.ControlRefused, match="supervisor"):
        control.start(path)
    assert cloud.state == "stopped" and cloud.starts == 0
    control.record_heartbeat(path, pid=os.getpid())
    control.start(path)
    assert cloud.state == "running" and cloud.starts == 1
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_watchdog_stops_after_worker_crash(tmp_path: Path) -> None:
    _module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())
    control.start(path)
    # No worker heartbeat is supplied: the independent supervisor owns cleanup.
    control.watch(path)
    assert cloud.stops and cloud.stops[0] < 1_180.0
    assert cloud.state == "stopped" and cloud.owner is None
    assert control.read(path)["state"] == "stopped"


def test_ambiguous_start_response_is_still_stopped(tmp_path: Path) -> None:
    _module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())
    cloud.fail_start_response = True
    with pytest.raises(TimeoutError):
        control.start(path)
    assert control.read(path)["start_requested"] is True
    control.watch(path)
    assert cloud.state == "stopped" and cloud.stops


@pytest.mark.parametrize("state,owner", [("running", None), ("stopped", "another-task")])
def test_preexisting_work_is_never_taken_over(tmp_path: Path, state: str, owner: str | None) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    cloud.state, cloud.owner = state, owner
    path = tmp_path / "receipt.json"
    with pytest.raises(module.ControlRefused):
        control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    assert not path.exists() and cloud.starts == 0 and cloud.stops == []


def test_changed_instance_owner_refuses_stop(tmp_path: Path) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())
    control.start(path)
    cloud.owner = "another-task"
    with pytest.raises(module.ControlRefused, match="owner"):
        control.stop(path)
    assert cloud.state == "running" and cloud.stops == []


@pytest.mark.parametrize("duration", [30, 7_201, -1])
def test_unbounded_or_too_short_deadline_is_rejected(tmp_path: Path, duration: int) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    with pytest.raises(module.ControlRefused, match="deadline"):
        control.arm(tmp_path / "receipt.json", instance=INSTANCE, deadline=clock.now() + duration)
    assert cloud.starts == 0


def test_expiring_credentials_cannot_arm_compute(tmp_path: Path) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    cloud.expiration = clock.now() + 120
    with pytest.raises(module.ControlRefused, match="credential"):
        control.arm(tmp_path / "receipt.json", instance=INSTANCE, deadline=clock.now() + 180)
    assert cloud.starts == 0


def test_existing_receipt_is_not_overwritten(tmp_path: Path) -> None:
    module, clock, _cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    path.write_bytes(b"existing retained evidence")
    with pytest.raises(module.ControlRefused):
        control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    assert path.read_bytes() == b"existing retained evidence"


def test_stale_supervisor_cannot_start_compute(tmp_path: Path) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())
    clock.value += 30
    with pytest.raises(module.ControlRefused, match="supervisor"):
        control.start(path)
    assert cloud.starts == 0


def test_unknown_instance_is_not_armed(tmp_path: Path) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    with pytest.raises(module.ControlRefused, match="instance"):
        control.arm(tmp_path / "receipt.json", instance="i-00000000000000000", deadline=clock.now() + 180)
    assert cloud.starts == 0


def test_cli_refuses_symlink_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.stop(path)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(module, "AwsCli", lambda *_args: cloud)
    assert module.main(["verify", "--evidence", str(link)]) == 1
    assert cloud.stops == []


def test_windows_liveness_never_uses_a_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    module = acceptance_tool("dbcrypt_acceptance_control")
    closed = []

    def opened(*_args):
        return 42

    def exited(_handle, output):
        output._obj.value = 259  # STILL_ACTIVE
        return 1

    def close(handle):
        closed.append(handle)
        return 1

    kernel = SimpleNamespace(OpenProcess=opened, GetExitCodeProcess=exited, CloseHandle=close)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel, raising=False)
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.os, "kill", lambda *_args: pytest.fail("liveness must not signal a Windows process"))
    assert module._alive(12345) is True
    assert closed == [42]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX controller process harness; Windows guest has its own gate")
def test_detached_supervisor_survives_worker_exit_and_source_change(tmp_path: Path) -> None:
    module, _clock, _cloud, control = controller(tmp_path / "admission")
    now = time.time()
    path = tmp_path / "receipt.json"
    state = tmp_path / "cloud.json"
    owner = "f" * 32
    state.write_text(json.dumps({"state": "running", "owner": owner}))
    path.write_text(
        json.dumps(
            dict(
                version=1,
                instance=INSTANCE,
                run=owner,
                account="123456789012",
                created=now - 120,
                deadline=now + 30,
                state="running",
                start_requested=True,
                supervisor_pid=None,
                heartbeat=None,
            )
        )
    )
    path.chmod(0o600)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_aws_executable(fake_bin / "aws", state)
    source = tmp_path / "operator.py"
    source_text = Path(module.__file__).read_text()
    default = 'self.admission_directory = Path.home() / ".cache" / "mordred-dbcrypt-control"'
    assert source_text.count(default) == 1, "keep the detached fixture isolated from the real controller directory"
    source.write_text(source_text.replace(default, f"self.admission_directory = Path({str(tmp_path / 'admission')!r})"))
    worker = (
        "import importlib.util; from pathlib import Path; "
        f"s=importlib.util.spec_from_file_location('operator_control', {str(source)!r}); "
        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
        f"print(m._launch_supervisor(Path({str(path)!r})), flush=True)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", worker],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]},
    )
    pid = int(completed.stdout.strip())
    source.write_text("raise RuntimeError('the worker checkout changed')\n")
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and control.read(path)["state"] != "stopped":
            time.sleep(0.05)
        supervisor_log = path.with_suffix(".supervisor.log")
        assert control.read(path)["state"] == "stopped", (
            supervisor_log.read_text() if supervisor_log.exists() else "no supervisor log"
        )
        observed = json.loads(state.read_text())
        assert observed["state"] == "stopped" and observed["owner"] is None
        assert observed["stopped_at"] < now + 30
    finally:
        import psutil

        try:
            process = psutil.Process(pid)
            if str(path.with_suffix(".supervisor.py")) in process.cmdline():
                process.terminate()
        except psutil.Error:
            pass


def test_inflight_start_cannot_outlive_verified_stop(tmp_path: Path) -> None:
    _module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())
    entered, release, stop_returned = threading.Event(), threading.Event(), threading.Event()
    original_start = cloud.start
    errors = []

    def delayed_start(instance: str) -> None:
        entered.set()
        assert release.wait(5)
        original_start(instance)

    def start() -> None:
        try:
            control.start(path)
        except Exception as exc:
            errors.append(exc)

    def stop() -> None:
        try:
            control.stop(path)
        except Exception as exc:
            errors.append(exc)
        finally:
            stop_returned.set()

    cloud.start = delayed_start
    starter = threading.Thread(target=start)
    stopper = threading.Thread(target=stop)
    starter.start()
    assert entered.wait(5)
    stopper.start()
    try:
        assert not stop_returned.wait(0.2), "stop must not release ownership while start is in flight"
    finally:
        release.set()
        starter.join(5)
        stopper.join(5)
    assert not starter.is_alive() and not stopper.is_alive() and not errors
    assert cloud.state == "stopped" and cloud.owner is None


def test_slow_admission_rechecks_deadline_before_start(tmp_path: Path) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())
    original_claim = cloud.claim

    def slow_claim(instance: str, owner: str) -> None:
        original_claim(instance, owner)
        clock.sleep(121)

    cloud.claim = slow_claim
    with pytest.raises(module.ControlRefused, match="deadline"):
        control.start(path)
    assert cloud.starts == 0
    control.watch(path)
    assert cloud.state == "stopped" and cloud.owner is None


def test_uncertain_start_retains_owner_until_delayed_activation(tmp_path: Path) -> None:
    _module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())

    def accepted_but_delayed(_instance: str) -> None:
        raise TimeoutError("accepted remotely; response lost before visibility")

    cloud.start = accepted_but_delayed
    with pytest.raises(TimeoutError):
        control.start(path)
    control.stop(path)
    assert cloud.owner is not None, "an uncertain stopped observation must not retire the guard"
    assert control.read(path)["state"] != "stopped"
    original_observe = cloud.observe

    def eventually_visible(instance: str) -> tuple[str, str | None]:
        if clock.now() >= 1_130 and not cloud.stops:
            cloud.state = "running"
        return original_observe(instance)

    cloud.observe = eventually_visible
    control.watch(path)
    assert cloud.stops and cloud.stops[0] < 1_180
    assert cloud.state == "stopped" and cloud.owner is None


def test_receipt_write_failure_still_stops_and_preserves_supervision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, clock, cloud, control = controller(tmp_path / "admission")
    path = tmp_path / "receipt.json"
    control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
    control.record_heartbeat(path, pid=os.getpid())
    control.start(path)

    def full(*_args, **_kwargs):
        raise OSError(28, "synthetic full evidence volume")

    class ObservedRetry(Exception):
        pass

    def observe_retry(_duration: float) -> None:
        assert cloud.stops and cloud.state == "stopped"
        assert cloud.owner is not None, "do not retire cleanup until evidence recovers"
        raise ObservedRetry

    monkeypatch.setattr(module, "_write", full)
    control.sleep = observe_retry
    with pytest.raises(ObservedRetry):
        control.watch(path)


def test_separate_receipts_cannot_overwrite_another_start(tmp_path: Path) -> None:
    module, clock, cloud, first = controller(tmp_path / "admission")
    second = module.Controller(cloud, now=clock.now, sleep=clock.sleep)
    second.admission_directory = tmp_path / "admission"
    paths = [tmp_path / "first.json", tmp_path / "second.json"]
    for path, control in zip(paths, (first, second), strict=True):
        control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
        control.record_heartbeat(path, pid=os.getpid())
    entered, release = threading.Event(), threading.Event()
    original_observe = cloud.observe
    delayed = False

    def observe(instance: str) -> tuple[str, str | None]:
        nonlocal delayed
        result = original_observe(instance)
        if threading.current_thread().name == "first-start" and not delayed:
            delayed = True
            entered.set()
            assert release.wait(5)
        return result

    def overwrite(_instance: str, owner: str) -> None:
        cloud.owner = owner  # Real EC2 CreateTags overwrites, without CAS.

    cloud.observe, cloud.claim = observe, overwrite
    outcomes = {}

    def start(index: int, control) -> None:
        try:
            control.start(paths[index])
            outcomes[index] = "started"
        except module.ControlRefused:
            outcomes[index] = "refused"

    a = threading.Thread(target=start, name="first-start", args=(0, first))
    b = threading.Thread(target=start, name="second-start", args=(1, second))
    a.start()
    assert entered.wait(5)
    b.start()
    try:
        b.join(0.2)
    finally:
        release.set()
        a.join(5)
        b.join(5)
    assert not a.is_alive() and not b.is_alive()
    assert sorted(outcomes.values()) == ["refused", "started"]
    winner = next(index for index, value in outcomes.items() if value == "started")
    control = (first, second)[winner]
    assert cloud.owner == control.read(paths[winner])["run"]
    control.stop(paths[winner])
    assert cloud.state == "stopped" and cloud.owner is None


def test_stale_describe_cannot_replace_canonical_local_run(tmp_path: Path) -> None:
    module, clock, cloud, first = controller(tmp_path / "admission")
    second = module.Controller(cloud, now=clock.now, sleep=clock.sleep)
    second.admission_directory = first.admission_directory
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    for path, control in ((a, first), (b, second)):
        control.arm(path, instance=INSTANCE, deadline=clock.now() + 180)
        control.record_heartbeat(path, pid=os.getpid())
    first.start(a)
    first_owner = cloud.owner
    original_observe = cloud.observe
    cloud.observe = lambda _instance: ("stopped", None)  # A stale AWS describe.
    cloud.claim = lambda _instance, owner: setattr(cloud, "owner", owner)
    with pytest.raises(module.ControlRefused):
        second.start(b)
    assert cloud.owner == first_owner
    cloud.observe = original_observe
    first.stop(a)
