"""Native Windows Tor route lifecycle with a stub ``tor.exe`` (and an optional real Tor).

Host-skipped. The stub is a real console ``.exe``: pip's vendored distlib
launcher (from pip, standalone distlib or ensurepip's bundled pip wheel)
with an appended zip whose ``__main__.py`` prints Tor's bootstrap lines and
writes a control cookie, exactly like a console-script launcher.
It exercises the real resolver/admission, checked private ``tor-data``,
``CREATE_NO_WINDOW`` launch, kill-on-close job, psutil identities, startup
cleanup and teardown. No network route is configured and no system setting
is changed.

The real-Tor case runs only with ``MORDRED_TEST_REAL_TOR=<absolute tor.exe>``
and the ``integration`` marker; it needs outbound network to bootstrap.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import textwrap
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path

import psutil
import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.network import _windows_exec as wexec
from mordred_hermes.network._exceptions import BringupFailed
from mordred_hermes.network._windows_job import KillOnCloseJob
from mordred_hermes.network.paths import _tor_windows as wtor
from mordred_hermes.network.paths import tor

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows process, job and ACL behavior")

STUB_MAIN = textwrap.dedent(
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
    for line in torrc.read_text(encoding="utf-8").splitlines():
        if line.startswith("DataDirectory "):
            data = pathlib.Path(unquote(line[len("DataDirectory "):]))
            (data / "control_auth_cookie").write_bytes(os.urandom(32))
    print("Tor 0.4.8 (stub) opening log", flush=True)
    print("Bootstrapped 100% (done): Done", flush=True)
    while True:
        time.sleep(0.2)
    """
)


def _distlib_launcher() -> bytes:
    # A uv-created venv has no pip; ensurepip's bundled pip wheel carries the
    # same vendored launcher and is read in place, never installed.
    for name in ("pip._vendor.distlib", "distlib"):
        try:
            spec = importlib.util.find_spec(name)
        except ImportError:
            spec = None
        for location in list(spec.submodule_search_locations or []) if spec is not None else []:
            candidate = Path(location) / "t64.exe"
            if candidate.is_file():
                return candidate.read_bytes()
    try:
        import ensurepip
    except ImportError:
        ensurepip = None
    bundled = Path(ensurepip.__file__).parent / "_bundled" if ensurepip is not None else None
    for wheel in sorted(bundled.glob("pip-*.whl")) if bundled is not None and bundled.is_dir() else []:
        with zipfile.ZipFile(wheel) as archive, contextlib.suppress(KeyError):
            return archive.read("pip/_vendor/distlib/t64.exe")
    pytest.skip("no distlib t64.exe launcher (pip, distlib or ensurepip's bundled pip) in this environment")


def stub_exe_bytes() -> bytes:
    executable = sys.executable
    if " " in executable:
        executable = f'"{executable}"'
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("__main__.py", STUB_MAIN)
    return _distlib_launcher() + b"#!" + executable.encode("utf-8") + b"\n" + archive.getvalue()


@pytest.fixture
def private_stub(tmp_path: Path) -> Path:
    """A current-user stub in a checked private directory (spaces + Unicode)."""
    directory = tmp_path / "トール bin"
    with open_private_directory(directory, create=True) as checked, checked.transaction() as txn:
        txn.create_bytes("tor.exe", stub_exe_bytes())
    return directory / "tor.exe"


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    home = tmp_path / "ホーム home"
    with open_private_directory(home, create=True):
        pass
    with open_private_directory(home / "mordred", create=True):
        pass
    return home / "mordred" / "tor-data"


def render(data_dir: Path) -> str:
    return tor.render_torrc(
        socks_port=9050, control_port=9051, data_dir=data_dir, quote_paths=True, owning_controller_pid=os.getpid()
    )


def record_bytes(data_dir: Path) -> bytes | None:
    with open_private_directory(data_dir) as directory:
        try:
            return directory.read_bytes(wtor.DAEMON_STATE, max_bytes=wtor.MAX_DAEMON_STATE_BYTES)
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return None
            raise


def wait_gone(pid: int, seconds: float = 20.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            return True
        with contextlib.suppress(psutil.NoSuchProcess):
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        time.sleep(0.1)
    return False


@contextlib.contextmanager
def launched(binary: Path | str, data_dir: Path, policy_mode: str = "strict") -> Iterator[tor.TorHandle]:
    process = tor.start_process(binary=str(binary), torrc=render(data_dir), data_dir=data_dir, policy_mode=policy_mode)  # type: ignore[arg-type]
    handle = tor.TorHandle(process=process, socks_port=9050, control_port=9051, data_dir=data_dir)
    try:
        yield handle
    finally:
        tor.stop(handle, grace_seconds=5.0)


def test_native_job_object_ends_its_member_on_close() -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        job = KillOnCloseJob()
        job.assign(child.pid)
        job.close()
        assert child.wait(timeout=10) is not None
    finally:
        if child.poll() is None:
            child.kill()


def test_native_job_member_dies_with_a_crashed_parent() -> None:
    script = textwrap.dedent(
        """
        import subprocess, sys, time
        from mordred_hermes.network._windows_job import KillOnCloseJob
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        job = KillOnCloseJob()
        job.assign(child.pid)
        print(child.pid, flush=True)
        time.sleep(120)
        """
    )
    parent = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    assert parent.stdout is not None
    child_pid = int(parent.stdout.readline())
    parent.kill()  # TerminateProcess: no Python cleanup runs in the parent
    parent.wait(timeout=10)
    assert wait_gone(child_pid)


def test_native_stub_tor_lifecycle_records_and_removes_exact_state(private_stub: Path, data_dir: Path) -> None:
    resolved = wexec.resolve_windows_executable(str(private_stub), purpose="tor")
    assert resolved.trust == "user-private"
    with launched(private_stub, data_dir) as handle:
        tor.wait_for_bootstrap(handle.process, timeout=60.0)
        process = handle.process
        assert isinstance(process, wtor.WindowsTorProcess)
        assert psutil.Process(process.pid).create_time() == process.identity.create_time
        assert record_bytes(data_dir) is not None
        # Tor-created cookie: token default DACL, admitted by the checked bounded reader.
        deadline = time.monotonic() + 10
        while wtor.control_cookie_state(data_dir) == "missing" and time.monotonic() < deadline:
            time.sleep(0.1)
        assert wtor.control_cookie_state(data_dir) == "ok"
        pid = process.pid
    assert wait_gone(pid)
    assert record_bytes(data_dir) is None


def test_native_crashed_parent_tor_dies_and_its_stale_record_is_forgotten(
    private_stub: Path, data_dir: Path, tmp_path: Path
) -> None:
    helper = tmp_path / "helper.py"
    helper.write_text(
        textwrap.dedent(
            """
            import os, sys, time
            from pathlib import Path
            from mordred_hermes.network.paths import tor
            data_dir, stub = Path(sys.argv[1]), sys.argv[2]
            torrc = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=data_dir,
                                     quote_paths=True, owning_controller_pid=os.getpid())
            process = tor.start_process(binary=stub, torrc=torrc, data_dir=data_dir, policy_mode="strict")
            tor.wait_for_bootstrap(process, timeout=60)
            print(process.pid, flush=True)
            time.sleep(600)
            """
        ),
        encoding="utf-8",
    )
    parent = subprocess.Popen(
        [sys.executable, str(helper), str(data_dir), str(private_stub)], stdout=subprocess.PIPE, text=True
    )
    assert parent.stdout is not None
    tor_pid = int(parent.stdout.readline())
    parent.kill()
    parent.wait(timeout=10)
    assert wait_gone(tor_pid)
    assert record_bytes(data_dir) is not None  # stale record left by the crash
    with launched(private_stub, data_dir) as handle:
        tor.wait_for_bootstrap(handle.process, timeout=60.0)
        assert handle.process.pid != tor_pid  # type: ignore[attr-defined]


def test_native_unrecorded_tor_on_this_profile_is_refused(private_stub: Path, data_dir: Path) -> None:
    with open_private_directory(data_dir, create=True):
        pass
    # Any current-user process naming this profile's torrc counts; it need not be Tor.
    orphan = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)", "-f", str(data_dir / "torrc")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with pytest.raises(BringupFailed, match="unrecorded Tor"):
            tor.start_process(
                binary=str(private_stub), torrc=render(data_dir), data_dir=data_dir, policy_mode="lenient"
            )
        assert orphan.poll() is None
    finally:
        orphan.kill()
        orphan.wait(timeout=10)


def test_native_untrusted_image_strict_refuses_lenient_launches(tmp_path: Path, data_dir: Path) -> None:
    shared = tmp_path / "shared downloads"
    shared.mkdir()
    subprocess.run(["icacls.exe", str(shared), "/grant", "*S-1-1-0:(OI)(CI)(M)"], check=True, capture_output=True)
    image = shared / "tor.exe"
    image.write_bytes(stub_exe_bytes())
    assert wexec.resolve_windows_executable(str(image), purpose="tor").trust == "untrusted"
    with pytest.raises(wexec.ExecutableRefused):
        tor.start_process(binary=str(image), torrc=render(data_dir), data_dir=data_dir, policy_mode="strict")
    assert not data_dir.exists()
    with launched(image, data_dir, policy_mode="lenient") as handle:
        tor.wait_for_bootstrap(handle.process, timeout=60.0)


def test_native_existing_unsafe_tor_data_refuses_without_repair(private_stub: Path, data_dir: Path) -> None:
    data_dir.mkdir()  # token default DACL, not the exact private ACL
    before = subprocess.run(
        ["icacls.exe", str(data_dir)], check=True, capture_output=True, text=True, encoding="utf-8", errors="replace"
    ).stdout
    with pytest.raises(BringupFailed, match="tor-data"):
        tor.start_process(binary=str(private_stub), torrc=render(data_dir), data_dir=data_dir, policy_mode="lenient")
    after = subprocess.run(
        ["icacls.exe", str(data_dir)], check=True, capture_output=True, text=True, encoding="utf-8", errors="replace"
    ).stdout
    assert after == before
    assert list(data_dir.iterdir()) == []


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("MORDRED_TEST_REAL_TOR"), reason="set MORDRED_TEST_REAL_TOR to tor.exe")
@pytest.mark.parametrize("home_name", ["home", "ホーム home #1"])
def test_native_real_tor_bootstraps_and_tears_down_exactly(tmp_path: Path, home_name: str) -> None:
    """ASCII and non-ASCII/space/'#' profile paths are recorded separately."""
    home = tmp_path / home_name
    with open_private_directory(home, create=True):
        pass
    with open_private_directory(home / "mordred", create=True):
        pass
    data_dir = home / "mordred" / "tor-data"
    binary = os.environ["MORDRED_TEST_REAL_TOR"]
    policy = os.environ.get("MORDRED_TEST_REAL_TOR_POLICY", "strict")
    port = tor.pick_free_port(candidates=(19050, 19150, 29050, 39050))
    torrc = tor.render_torrc(
        socks_port=port,
        control_port=port + 1,
        data_dir=data_dir,
        disable_ipv6=True,
        quote_paths=True,
        owning_controller_pid=os.getpid(),
    )
    process = tor.start_process(binary=binary, torrc=torrc, data_dir=data_dir, policy_mode=policy)  # type: ignore[arg-type]
    handle = tor.TorHandle(process=process, socks_port=port, control_port=port + 1, data_dir=data_dir)
    try:
        tor.wait_for_bootstrap(process, timeout=300.0)
        assert wtor.control_cookie_state(data_dir) == "ok"
        if importlib.util.find_spec("stem") is not None:
            from stem.control import Controller

            # Tor's reported COOKIEFILE must be the private cookie (raises a
            # classified ControlCookiePathRefused otherwise, e.g. on a
            # non-ASCII profile path Tor reports in another encoding).
            with Controller.from_port(address="127.0.0.1", port=port + 1) as controller:
                wtor.pinned_protocolinfo(controller, data_dir)
            assert tor.circuit_status_health(handle) is True
        print(f"real tor pid={process.pid} trust={getattr(process, 'image_trust', None)} port={port}")
    finally:
        tor.stop(handle, grace_seconds=10.0)
    assert process.poll() is not None
    assert record_bytes(data_dir) is None
