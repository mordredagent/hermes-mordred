"""Actual NTFS coordinator locks, inherited descriptors and interrupted writers."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mordred_hermes._config_io import (
    CanonicalPaths,
    PolicyPendingError,
    canonical_session,
    read_canonical_snapshot,
)
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows canonical coordination")


def line(process):
    output = queue.Queue()
    threading.Thread(target=lambda: output.put(process.stdout.readline().strip()), daemon=True).start()
    return output.get(timeout=20)


def test_native_noop_preserves_inherited_descriptor_and_case_nesting(shared_home):
    paths = CanonicalPaths(shared_home)
    parent_before = descriptor(shared_home)
    config_before = descriptor(shared_home / "config.yaml")
    with canonical_session(paths, scope="policy", create=True) as session:
        with canonical_session(CanonicalPaths(Path(str(shared_home).upper())), scope="home") as nested:
            assert nested.read_pair().config.data == b"old"
        with session.policy_update() as update:
            update.put_config(b"old")
            update.commit()
    assert descriptor(shared_home) == parent_before
    assert descriptor(shared_home / "config.yaml") == config_before


def test_native_reader_in_fresh_process_fails_closed_on_busy(shared_home):
    program = """
import sys
from pathlib import Path
from mordred_hermes._config_io import CanonicalPaths, read_canonical_snapshot
from mordred_hermes._private_fs import PrivateFSError
try:
    read_canonical_snapshot(CanonicalPaths(Path(sys.argv[1])))
except PrivateFSError as exc:
    print(exc.reason)
else:
    raise AssertionError("reader entered a locked pair")
"""
    with canonical_session(CanonicalPaths(shared_home), scope="policy", create=True):
        result = subprocess.run(
            [sys.executable, "-c", program, str(shared_home)], check=True, capture_output=True, text=True, timeout=20
        )
        assert result.stdout.strip() == "busy"


def test_native_crash_between_members_leaves_marker_until_explicit_recovery(shared_home):
    program = """
import sys
from pathlib import Path
from mordred_hermes._config_io import CanonicalPaths, canonical_session
from mordred_hermes._private_fs import _windows_io
original = _windows_io._Transaction.create_bytes
def paused(self, name, data):
    if name == "policy.json":
        print("partial", flush=True)
        sys.stdin.readline()
    return original(self, name, data)
_windows_io._Transaction.create_bytes = paused
paths = CanonicalPaths(Path(sys.argv[1]))
with canonical_session(paths, scope="policy", create=True) as session, session.policy_update() as update:
    update.put_config(b"new")
    update.put_policy(b"{}")
    update.commit()
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", program, str(shared_home)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    paths = CanonicalPaths(shared_home)
    try:
        assert line(child) == "partial"
        from mordred_hermes._private_fs import PrivateFSError

        with pytest.raises(PrivateFSError) as err:
            read_canonical_snapshot(paths)
        assert err.value.reason == "busy"
        child.kill()
        child.wait(timeout=20)
        with pytest.raises(PolicyPendingError):
            read_canonical_snapshot(paths)
        with canonical_session(paths, scope="policy") as session, session.policy_update(recover_pending=True) as update:
            assert session.read_pair().config.data == b"new"
            update.put_config(b"new")
            update.put_policy(b"{}")
            update.commit()
        snapshot = read_canonical_snapshot(paths)
        assert snapshot.config.data == b"new" and snapshot.policy.data == b"{}"
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=20)
