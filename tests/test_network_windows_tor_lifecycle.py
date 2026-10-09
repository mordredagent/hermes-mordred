"""Native Windows Tor lifecycle, host-emulated: private state, cleanup and exact teardown.

The cases use the real checked private directory of this host, a real stub
child process (a Python script standing in for ``tor.exe``), real psutil
identities and a fake kill-on-close job. No Tor, VPN, registry or network
setting is touched. Discovery, torrc rendering, the bounded reader and the
cookie check are in ``test_network_windows_tor.py``.
"""

from __future__ import annotations

import contextlib
import json
import ntpath
import os
import subprocess
import sys
import textwrap
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import psutil
import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.network import _windows_exec as wexec
from mordred_hermes.network._exceptions import BringupFailed
from mordred_hermes.network.paths import _tor_windows as wtor
from mordred_hermes.network.paths import tor

MANAGED = r"C:\Program Files\Tor Browser\Tor\tor.exe"
UNTRUSTED = r"C:\Users\Public\Downloads\tor.exe"


# --------------------------------------------------------------------------- #
# Lifecycle with a real stub child process                                    #
# --------------------------------------------------------------------------- #

STUB_TOR = textwrap.dedent(
    r"""
    import os, pathlib, sys, time

    def unquote(value):
        if not value.startswith('"'):
            return value
        out, index = [], 1
        while value[index] != '"':
            if value[index] == "\\":
                index += 1
            out.append(value[index])
            index += 1
        return "".join(out)

    args = sys.argv[1:]
    torrc = pathlib.Path(args[args.index("-f") + 1])
    data = None
    for line in torrc.read_text(encoding="utf-8").splitlines():
        if line.startswith("DataDirectory "):
            data = pathlib.Path(unquote(line[len("DataDirectory "):]))
    if data is not None and os.environ.get("STUB_TOR_COOKIE") == "1":
        (data / "control_auth_cookie").write_bytes(os.urandom(32))
    print("Tor 0.4.8 (stub) opening log", flush=True)
    print("Bootstrapped 5% (conn): Connecting to a relay", flush=True)
    print("Bootstrapped 100% (done): Done", flush=True)
    while True:
        time.sleep(0.2)
    """
)


@pytest.fixture
def stub_script(tmp_path: Path) -> Path:
    script = tmp_path / "stub_tor.py"
    script.write_text(STUB_TOR, encoding="utf-8")
    return script


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    home = tmp_path / "ホーム home"
    with open_private_directory(home, create=True):
        pass
    with open_private_directory(home / "mordred", create=True):
        pass
    return home / "mordred" / "tor-data"


class StubPopen:
    """Runs the stub script for the resolved image; records the exact launch."""

    def __init__(self, script: Path) -> None:
        self.script = script
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.children: list[subprocess.Popen[str]] = []

    def __call__(self, argv: Any, **kwargs: Any) -> subprocess.Popen[str]:
        self.calls.append((argv, kwargs))
        child = subprocess.Popen(
            [sys.executable, str(self.script), *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.children.append(child)
        return child

    def reap(self) -> None:
        for child in self.children:
            if child.poll() is None:
                child.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=5)
            if child.stdout is not None:
                child.stdout.close()


class FakeJob:
    """Kill-on-close job stand-in: closing ends exactly its assigned members."""

    instances: ClassVar[list[FakeJob]] = []

    def __init__(self, *, assign_error: BaseException | None = None) -> None:
        self.assigned: list[int] = []
        self.closed = False
        self.assign_error = assign_error
        FakeJob.instances.append(self)

    def assign(self, pid: int) -> None:
        if self.assign_error is not None:
            raise self.assign_error
        self.assigned.append(pid)

    def close(self) -> None:
        self.closed = True
        for pid in self.assigned:
            with contextlib.suppress(psutil.NoSuchProcess):
                psutil.Process(pid).kill()


def make_system(popen: Any, **overrides: Any) -> wtor.WindowsTorSystem:
    values: dict[str, Any] = {
        "resolve": lambda binary: wexec.ResolvedExecutable(MANAGED, "managed"),
        "open_state": lambda path: open_private_directory(path, create=True),
        "popen": popen,
        "new_job": FakeJob,
        "identify": wtor.identify_process,
        "owner": wtor.current_owner,
        "owner_alive": wtor.owner_alive,
        "terminate": wtor.terminate_identity,
        "scan": lambda torrc_path: (),
    }
    values.update(overrides)
    return wtor.WindowsTorSystem(**values)


def torrc_for(data_dir: Path) -> str:
    return tor.render_torrc(
        socks_port=9050, control_port=9051, data_dir=data_dir, quote_paths=True, owning_controller_pid=os.getpid()
    )


def read_state(data_dir: Path, name: str) -> bytes | None:
    with open_private_directory(data_dir) as directory:
        try:
            return directory.read_bytes(name, max_bytes=1 << 20)
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return None
            raise


def write_record(data_dir: Path, record: dict[str, Any] | bytes) -> None:
    raw = record if isinstance(record, bytes) else json.dumps(record).encode()
    with open_private_directory(data_dir, create=True) as directory, directory.transaction() as txn:
        txn.create_bytes(wtor.DAEMON_STATE, raw)


def spawn_sleeper(*args: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time\nwhile True: time.sleep(0.2)", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def identity_record(
    pid: int, *, owner: tuple[int, float], torrc: str = "torrc", exe: str | None = None
) -> dict[str, Any]:
    process = psutil.Process(pid)
    return {
        "schema": 1,
        "tor": {
            "pid": pid,
            "create_time": process.create_time(),
            "exe": exe if exe is not None else process.exe(),
            "username": process.username(),
        },
        "owner": {"pid": owner[0], "create_time": owner[1]},
        "torrc": torrc,
    }


@pytest.fixture
def launcher(stub_script: Path) -> Iterator[StubPopen]:
    popen = StubPopen(stub_script)
    FakeJob.instances.clear()
    try:
        yield popen
    finally:
        popen.reap()


def handle_for(process: Any, data_dir: Path) -> tor.TorHandle:
    return tor.TorHandle(process=process, socks_port=9050, control_port=9051, data_dir=data_dir)


def test_windows_launch_records_the_exact_identity_and_tears_down_only_it(data_dir: Path, launcher: StubPopen) -> None:
    torrc = torrc_for(data_dir)
    process = wtor.start_process(
        binary="tor", torrc=torrc, data_dir=data_dir, policy_mode="strict", system=make_system(launcher)
    )
    [(argv, kwargs)] = launcher.calls
    torrc_path, defaults_path = str(data_dir / "torrc"), str(data_dir / "torrc-defaults")
    assert argv == [MANAGED, "-f", torrc_path, "--defaults-torrc", defaults_path]
    assert isinstance(argv, list)
    assert kwargs["executable"] == MANAGED
    assert kwargs["cwd"] == ntpath.dirname(MANAGED)
    assert kwargs["creationflags"] & wtor.CREATE_NO_WINDOW
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs.get("shell", False) is False
    # Private state: the torrc, an empty pinned defaults file, then the record.
    assert read_state(data_dir, "torrc") == torrc.encode()
    assert read_state(data_dir, "torrc-defaults") == b""
    raw = read_state(data_dir, wtor.DAEMON_STATE)
    assert raw is not None
    record = json.loads(raw)
    child = psutil.Process(process.pid)
    assert record["tor"] == {
        "pid": process.pid,
        "create_time": child.create_time(),
        "exe": child.exe(),
        "username": child.username(),
    }
    assert record["owner"] == {"pid": os.getpid(), "create_time": psutil.Process().create_time()}
    assert record["torrc"] == torrc_path
    [job] = FakeJob.instances
    assert job.assigned == [process.pid]

    tor.wait_for_bootstrap(process, timeout=20.0)
    tor.stop(handle_for(process, data_dir), grace_seconds=5.0)
    assert process.poll() is not None
    assert job.closed
    assert read_state(data_dir, wtor.DAEMON_STATE) is None


def test_existing_unsafe_tor_data_refuses_before_any_spawn(data_dir: Path, launcher: StubPopen) -> None:
    if os.name == "nt":
        pytest.skip("POSIX-mode damage; native ACL damage is in the native module")
    data_dir.mkdir(mode=0o755)
    data_dir.chmod(0o755)
    with pytest.raises(BringupFailed, match="tor-data"):
        wtor.start_process(
            binary="tor",
            torrc=torrc_for(data_dir),
            data_dir=data_dir,
            policy_mode="lenient",
            system=make_system(launcher),
        )
    assert launcher.calls == []


def test_unsafe_existing_torrc_refuses_before_any_spawn(data_dir: Path, launcher: StubPopen, tmp_path: Path) -> None:
    write_record_dir = data_dir
    with open_private_directory(write_record_dir, create=True) as directory, directory.transaction() as txn:
        txn.create_bytes("torrc", b"SOCKSPort 0.0.0.0:9050\n")
    os.link(data_dir / "torrc", tmp_path / "torrc-alias")
    with pytest.raises(BringupFailed):
        wtor.start_process(
            binary="tor",
            torrc=torrc_for(data_dir),
            data_dir=data_dir,
            policy_mode="strict",
            system=make_system(launcher),
        )
    assert launcher.calls == []


def test_untrusted_image_refuses_in_strict_before_state_or_spawn(data_dir: Path, launcher: StubPopen) -> None:
    system = make_system(launcher, resolve=lambda binary: wexec.ResolvedExecutable(UNTRUSTED, "untrusted"))
    with pytest.raises(wexec.ExecutableRefused):
        wtor.start_process(
            binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="strict", system=system
        )
    assert launcher.calls == []
    assert not data_dir.exists()


def test_untrusted_image_warns_and_launches_in_lenient(
    data_dir: Path, launcher: StubPopen, caplog: pytest.LogCaptureFixture
) -> None:
    system = make_system(launcher, resolve=lambda binary: wexec.ResolvedExecutable(UNTRUSTED, "untrusted"))
    with caplog.at_level("WARNING", logger="mordred.network"):
        process = wtor.start_process(
            binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="lenient", system=system
        )
    try:
        assert process.image_trust == "untrusted"
        assert any("untrusted" in record.getMessage() for record in caplog.records)
    finally:
        process.stop(grace_seconds=5.0)


def test_stale_record_for_an_exited_tor_is_discarded(data_dir: Path, launcher: StubPopen) -> None:
    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    record = identity_record(os.getpid(), owner=(os.getpid(), 1.0))
    gone.wait(timeout=10)
    record["tor"]["pid"] = gone.pid
    record["tor"]["create_time"] = 1.0
    write_record(data_dir, record)
    process = wtor.start_process(
        binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="strict", system=make_system(launcher)
    )
    try:
        new_record = json.loads(read_state(data_dir, wtor.DAEMON_STATE) or b"{}")
        assert new_record["tor"]["pid"] == process.pid
    finally:
        process.stop(grace_seconds=5.0)


def test_stale_tor_of_a_dead_owner_is_terminated_only_after_identity_revalidation(
    data_dir: Path, launcher: StubPopen
) -> None:
    stale = spawn_sleeper("stale-tor")
    try:
        # The owner identity names this pid with an impossible creation time:
        # that Mordred process no longer exists.
        write_record(data_dir, identity_record(stale.pid, owner=(os.getpid(), 1.0)))
        terminated: list[Any] = []

        def recording_terminate(identity: Any, timeout: float) -> bool:
            terminated.append(identity)
            return wtor.terminate_identity(identity, timeout)

        system = make_system(launcher, terminate=recording_terminate)
        process = wtor.start_process(
            binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="strict", system=system
        )
        try:
            assert [identity.pid for identity in terminated] == [stale.pid]
            assert stale.wait(timeout=10) is not None
            assert json.loads(read_state(data_dir, wtor.DAEMON_STATE) or b"{}")["tor"]["pid"] == process.pid
        finally:
            process.stop(grace_seconds=5.0)
    finally:
        if stale.poll() is None:
            stale.kill()
        stale.wait(timeout=10)


@pytest.mark.parametrize("mismatch", ["exe", "username"])
def test_identity_mismatch_refuses_without_stopping_anything(
    data_dir: Path, launcher: StubPopen, mismatch: str, caplog: pytest.LogCaptureFixture
) -> None:
    stale = spawn_sleeper("not-our-tor")
    try:
        record = identity_record(stale.pid, owner=(os.getpid(), 1.0))
        record["tor"][mismatch] = r"C:\Other\tor.exe" if mismatch == "exe" else "OTHER\\mallory"
        write_record(data_dir, record)
        before = read_state(data_dir, wtor.DAEMON_STATE)
        system = make_system(launcher, terminate=_never("terminate"))
        with caplog.at_level("WARNING", logger="mordred.network"), pytest.raises(BringupFailed, match="identity"):
            wtor.start_process(
                binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="lenient", system=system
            )
        # Lenient degrades with a warning; the runtime records the clearnet fallback.
        assert any("degrades to clearnet" in entry.getMessage() for entry in caplog.records)
        assert stale.poll() is None
        assert read_state(data_dir, wtor.DAEMON_STATE) == before
        assert launcher.calls == []
    finally:
        stale.kill()
        stale.wait(timeout=10)


def test_tor_owned_by_a_live_mordred_process_is_never_stopped_or_reused(data_dir: Path, launcher: StubPopen) -> None:
    stale = spawn_sleeper("live-tor")
    owner = spawn_sleeper("live-owner")
    try:
        write_record(data_dir, identity_record(stale.pid, owner=(owner.pid, psutil.Process(owner.pid).create_time())))
        system = make_system(launcher, terminate=_never("terminate"))
        with pytest.raises(BringupFailed, match="live Mordred process"):
            wtor.start_process(
                binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="strict", system=system
            )
        assert stale.poll() is None
        assert launcher.calls == []
    finally:
        for child in (stale, owner):
            child.kill()
            child.wait(timeout=10)


@pytest.mark.parametrize(
    "raw",
    [
        b"{not json mordred-secret-bytes",
        b'{"schema": 2}',
        json.dumps({"schema": 1, "tor": {}, "owner": {}, "torrc": "x"}).encode(),
        b'{"schema": 1, "extra": "mordred-secret-bytes"}',
        b"x" * (wtor.MAX_DAEMON_STATE_BYTES + 1),
    ],
)
def test_malformed_or_oversized_daemon_state_refuses_without_echoing_bytes(
    data_dir: Path, launcher: StubPopen, raw: bytes
) -> None:
    write_record(data_dir, raw)
    with pytest.raises(BringupFailed) as caught:
        wtor.start_process(
            binary="tor",
            torrc=torrc_for(data_dir),
            data_dir=data_dir,
            policy_mode="lenient",
            system=make_system(launcher),
        )
    assert "mordred-secret-bytes" not in str(caught.value)
    assert caught.value.__cause__ is None
    link: BaseException | None = caught.value
    while link is not None:
        # No retained parser exception may carry the document (JSONDecodeError.doc).
        assert "mordred-secret-bytes" not in repr(link) + str(getattr(link, "doc", ""))
        link = link.__cause__ or link.__context__
    assert launcher.calls == []
    assert read_state(data_dir, wtor.DAEMON_STATE) == raw


def test_an_unrecorded_tor_using_this_profile_is_refused_never_reused(data_dir: Path, launcher: StubPopen) -> None:
    torrc_path = str(data_dir / "torrc")
    orphan = spawn_sleeper("-f", torrc_path)
    try:
        system = make_system(launcher, scan=wtor.scan_torrc_users)
        with pytest.raises(BringupFailed, match="unrecorded Tor"):
            wtor.start_process(
                binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="strict", system=system
            )
        assert orphan.poll() is None
        assert launcher.calls == []
    finally:
        orphan.kill()
        orphan.wait(timeout=10)


def test_uncertain_process_inventory_refuses(data_dir: Path, launcher: StubPopen) -> None:
    def uncertain(_torrc_path: str) -> tuple[int, ...]:
        raise wtor.ProcessStateUncertain("inventory-limit")

    with pytest.raises(BringupFailed, match="inventory-limit"):
        wtor.start_process(
            binary="tor",
            torrc=torrc_for(data_dir),
            data_dir=data_dir,
            policy_mode="lenient",
            system=make_system(launcher, scan=uncertain),
        )
    assert launcher.calls == []


def test_job_assignment_failure_kills_the_child_and_records_nothing(data_dir: Path, launcher: StubPopen) -> None:
    system = make_system(launcher, new_job=lambda: FakeJob(assign_error=OSError(5, "access denied")))
    with pytest.raises(BringupFailed, match="job"):
        wtor.start_process(
            binary="tor", torrc=torrc_for(data_dir), data_dir=data_dir, policy_mode="lenient", system=system
        )
    [child] = launcher.children
    assert child.wait(timeout=10) is not None
    assert read_state(data_dir, wtor.DAEMON_STATE) is None
    assert FakeJob.instances[-1].closed


def test_spawn_failure_is_classified(data_dir: Path) -> None:
    def failing(argv: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError(2, "not found", argv[0])

    with pytest.raises(BringupFailed, match="could not be spawned"):
        wtor.start_process(
            binary="tor",
            torrc=torrc_for(data_dir),
            data_dir=data_dir,
            policy_mode="strict",
            system=make_system(failing),
        )
    assert read_state(data_dir, wtor.DAEMON_STATE) is None


def _never(name: str) -> Callable[..., Any]:
    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError(f"{name} must not be called")

    return fail


class FakeChild:
    """Popen stand-in recording handle-based termination only."""

    pid = 31337

    def __init__(self) -> None:
        self.alive = True
        self.terminations = 0
        self.stdout = None

    def poll(self) -> int | None:
        return None if self.alive else 1

    def wait(self, timeout: float | None = None) -> int:
        if self.alive:
            raise subprocess.TimeoutExpired("tor", timeout or 0)
        return 1

    def terminate(self) -> None:
        self.terminations += 1
        self.alive = False

    kill = terminate


def windows_process(child: FakeChild, identify: Callable[[int], Any], data_dir: Path) -> wtor.WindowsTorProcess:
    identity = wtor.ProcessIdentity(child.pid, 100.0, MANAGED, "HOST\\jane")
    job = FakeJob()
    system = make_system(_never("popen"), identify=identify)
    return wtor.WindowsTorProcess(
        popen=child, job=job, identity=identity, data_dir=data_dir, system=system, image_trust="managed"
    )


def test_teardown_terminates_through_the_creation_handle_after_identity_revalidation(data_dir: Path) -> None:
    child = FakeChild()
    process = windows_process(child, lambda pid: wtor.ProcessIdentity(pid, 100.0, MANAGED, "HOST\\jane"), data_dir)
    tor.stop(handle_for(process, data_dir), grace_seconds=0.01)
    assert child.terminations == 1
    assert FakeJob.instances[-1].closed


@pytest.mark.parametrize("current", [None, "reused"])
def test_teardown_never_terminates_a_different_process(data_dir: Path, current: str | None) -> None:
    child = FakeChild()

    def identify(pid: int) -> Any:
        if current is None:
            raise wtor.ProcessStateUncertain("process-access-denied")
        return wtor.ProcessIdentity(pid, 999.0, r"C:\Windows\notepad.exe", "HOST\\jane")

    process = windows_process(child, identify, data_dir)
    process.terminate()
    process.kill()
    assert child.terminations == 0
    # Only exact job membership remains as the termination authority.
    process.release()
    assert FakeJob.instances[-1].closed


def test_teardown_keeps_a_record_it_does_not_own(data_dir: Path) -> None:
    other = identity_record(os.getpid(), owner=(os.getpid(), 1.0))
    write_record(data_dir, other)
    child = FakeChild()
    child.alive = False
    process = windows_process(child, lambda pid: None, data_dir)
    process.release()
    assert json.loads(read_state(data_dir, wtor.DAEMON_STATE) or b"{}") == other


def test_tor_start_process_dispatches_to_the_windows_launcher(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    sentinel = object()

    def fake_start(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return sentinel

    monkeypatch.setattr(wtor, "start_process", fake_start)
    monkeypatch.setattr(sys, "platform", "win32")
    result = tor.start_process(binary="tor", torrc="x", data_dir=tmp_path, policy_mode="strict")
    assert result is sentinel
    assert calls == [{"binary": "tor", "torrc": "x", "data_dir": tmp_path, "policy_mode": "strict"}]
    with pytest.raises(BringupFailed):
        tor.start_process(binary="tor", torrc="x")
