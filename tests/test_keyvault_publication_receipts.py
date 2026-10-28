"""Actual process exclusion is the provisioning-receipt safety boundary."""

import json
import select
import subprocess
import sys

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import wrap
from tests._keyvault_receipt_ipc import make_backend
from tests._platform_test_helpers import legacy_secret_store as legacy_secret_store


def start(home, worker, role="main", stage="live"):
    return subprocess.Popen(
        [sys.executable, "-m", "tests._keyvault_receipt_ipc", str(home), worker, role, stage],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def read(process):
    assert select.select([process.stdout], [], [], 10)[0], "worker did not reach IPC boundary"
    line = process.stdout.readline()
    assert line, process.stderr.read()
    return json.loads(line)


def send(process, command):
    process.stdin.write(command + "\n")
    process.stdin.flush()


def finish(process):
    assert process.wait(timeout=10) == 0, process.stderr.read()


@pytest.mark.parametrize("role", ["main", "audit"])
@pytest.mark.parametrize("schedule", ["rollback", "commit", "expiry", "create-return", "rollback-lookup", "alias"])
def test_os_custody_excludes_second_real_producer(tmp_path, legacy_secret_store, role, schedule):
    a = start(tmp_path, "A", role, schedule)
    b = None
    alias = None
    try:
        if schedule == "create-return":
            assert read(a) == {"paused": schedule}
        else:
            original = read(a)
            assert original["ready"]
        if schedule == "rollback-lookup":
            send(a, "rollback")
            assert read(a) == {"paused": schedule}
        b_home = tmp_path
        if schedule == "alias":
            alias = tmp_path.with_name(tmp_path.name + "-alias")
            alias.symlink_to(tmp_path, target_is_directory=True)
            b_home = alias
        b = start(b_home, "B", role)
        assert read(b) == {"attempting": True}
        assert not select.select([b.stdout], [], [], 0.25)[0], "producer passed live OS custody"
        if schedule == "create-return":
            send(a, "continue")
            original = read(a)
            assert original["ready"]
            send(a, "rollback")
        elif schedule == "rollback-lookup":
            send(a, "continue")
        else:
            send(a, "exit" if schedule == "expiry" else "rollback" if schedule == "alias" else schedule)
        assert read(a) == {"old_rollback": "refused", "native_deletes": 0}
        finish(a)
        result = read(b)
        if schedule in ("rollback", "create-return", "rollback-lookup", "alias"):
            assert result == {"result": "published"}
            from mordred_hermes.keyvault import _native_key_id, _storage
            from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID

            latest, _ = make_backend(tmp_path)
            logical = "default" if role == "main" else AUDIT_LOG_KEY_ID
            physical = _native_key_id.scoped_native_key_id(_storage.resolve_keyvault_dir(tmp_path), logical)
            assert latest.get_enclave_public_key(physical).hex() != original["public"]
        finish(b)
    finally:
        for process in (a, b):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        if alias is not None:
            alias.unlink()


def test_linux_cross_process_adoption_has_no_arbitrary_receipt(tmp_path, legacy_secret_store):
    from mordred_hermes.keyvault import _memory_key as memory

    backend, ops = make_backend(tmp_path)
    selector = memory.memory_key_id(tmp_path)
    with pytest.raises(TypeError), wrap.create_wrapping_key_scope(selector, backend=backend):
        pytest.fail("arbitrary memory creation obtained a receipt")
    assert ops.calls == []
    backend.generate_enclave_key(selector, unattended=True)
    b = start(tmp_path, "linux")
    assert read(b) == {"published": True}
    finish(b)
    (tmp_path / "state.db").touch()
    with pytest.raises(DatabaseRefused):
        backend.delete_enclave_key(selector)
    assert memory.memory_key_path(tmp_path).exists()
    assert tuple((tmp_path / "native-store").iterdir())
    assert all(command != "delete" for command, _ in ops.calls)
