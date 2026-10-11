"""Independent writer processes using real lifecycle locks, MRKW, and MRAL."""

import subprocess
import sys
import time

import pytest

from mordred_hermes._private_fs import open_private_directory
from tests._windows_audit_process_fakes import ProcessBackend
from tests.test_private_fs_processes import _line
from tests.test_windows_encrypted_audit import audit_fs as audit_fixture  # noqa: F401
from tests.test_windows_encrypted_audit import checked_audit_boundary, custody_fixture  # noqa: F401

# Three writers contend for real locks; slow Windows runners (2 vCPU, Defender)
# need well over the old 30 s per child. A stalled writer still fails, with the
# faulthandler stacks each child prints to stderr after STACK_DUMP_SECONDS.
CHILDREN_DEADLINE_SECONDS = 120.0
STACK_DUMP_SECONDS = 60

_CHILD = f"""
import faulthandler
import sys

faulthandler.dump_traceback_later({STACK_DUMP_SECONDS})
import pytest
from pathlib import Path
from tests._windows_audit_process_fakes import ProcessBackend, install_boundaries
from mordred_hermes.keyvault._windows_custody import windows_custody_session
from mordred_hermes.keyvault.windows_audit import WindowsAuditProvider
install_boundaries()
home=Path(sys.argv[1]); backend=ProcessBackend()
with windows_custody_session(home, backend=backend) as custody:
    lease=custody.lease('audit')
backend.bind(lease.native_key_id)
writer=WindowsAuditProvider(home, backend=backend).writer(home/'mordred'/'audit.log', rotate_bytes=800)
for n in range(8): writer.append({{'worker':sys.argv[2], 'n':n}})
writer.close()
print('committed', flush=True)
"""


def test_multiprocess_append_rotation_format_and_custody_serialization(fs):
    from mordred_hermes.keyvault._windows_custody import windows_custody_session
    from mordred_hermes.keyvault.windows_audit import decrypt_windows_log_file

    _, _, home, _ = fs
    backend = ProcessBackend()
    with windows_custody_session(home, create=True, backend=backend) as custody:
        custody.enroll_role("audit")
    children = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(home), str(n)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for n in range(3)
    ]
    deadline = time.monotonic() + CHILDREN_DEADLINE_SECONDS
    try:
        for index, child in enumerate(children):
            try:
                out, err = child.communicate(timeout=max(1.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                stalled = []
                for other in children[index:]:
                    other.kill()
                    stalled.append(other.communicate(timeout=10)[1])
                pytest.fail("stalled audit writer children; stderr (faulthandler stacks):\n" + "\n---\n".join(stalled))
            assert child.returncode == 0, err
            assert out.strip() == "committed"
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
    path = home / "mordred" / "audit.log"
    entries = []
    for candidate in [path, *path.parent.glob("audit.log.*")]:
        entries += decrypt_windows_log_file(candidate, home=home, backend=backend, audit_sink=lambda event: None)
    assert sorted((event["worker"], event["n"]) for event in entries) == [
        (str(w), n) for w in range(3) for n in range(8)
    ]


def test_custom_directory_lock_contention_is_nonblocking(fs):
    from mordred_hermes.keyvault._windows_custody import windows_custody_session
    from mordred_hermes.keyvault.windows_audit import WindowsAuditProvider

    c, _, home, backend = fs
    with windows_custody_session(home, create=True, backend=backend):
        pass
    custom = home.parent / "custom"
    with open_private_directory(custom, create=True):
        pass
    script = """
import sys

import pytest
from pathlib import Path
from mordred_hermes._private_fs import open_private_directory
with open_private_directory(Path(sys.argv[1])) as directory, directory.transaction() as tx:
    print('ready', flush=True)
    sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(custom)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert _line(child) == "ready"
        with c.windows_custody_session(home, create=True, backend=backend) as session:
            session.enroll_role("audit")
        from mordred_hermes._private_fs import PrivateFSError

        with pytest.raises(PrivateFSError) as error:
            WindowsAuditProvider(home, backend=backend).writer(custom / "audit.log").append({"event": "refuse"})
        assert error.value.reason == "busy"
    finally:
        child.communicate(input="done\n", timeout=10)
    assert not (custom / "audit.log").exists()
