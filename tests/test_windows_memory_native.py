"""Real NTFS inherited memory admission, with only the CNG boundary injected."""

import os
import subprocess
import sys

import pytest

from mordred_hermes._private_fs import PrivateFSError
from mordred_hermes.keyvault import _memory_storage as storage
from mordred_hermes.keyvault import _windows_custody as custody
from mordred_hermes.keyvault.memory_crypto import is_sealed, seal, unseal
from tests._keyvault_fakes import FakeBackend
from tests.test_private_fs_confidential_windows import descriptor, powershell
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual NTFS memory storage")


def set_fixture_owner(path):
    powershell(
        path,
        """
        $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
        $a.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User);
        Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
        """,
    )


@pytest.fixture
def native_memory(shared_home, monkeypatch):
    home = shared_home
    memories = home / "memories"
    memories.mkdir()
    set_fixture_owner(memories)
    path = memories / "MEMORY.md"
    path.write_bytes(b"synthetic memory")
    set_fixture_owner(path)
    backend = FakeBackend()
    monkeypatch.setattr(custody, "windows_backend", lambda: backend)
    return home, backend


def test_native_inherited_memory_seal_keeps_parents_and_casing_aad(native_memory):
    home, backend = native_memory
    parent = descriptor(home)
    directory = descriptor(home / "memories")
    original_file = descriptor(home / "memories" / "MEMORY.md")
    assert "ID;" in original_file
    with custody.windows_custody_session(home, create=True, backend=backend) as owner:
        key = owner.enroll_memory()
    # Fixture publication creates an existing seal, without an arming ceremony.
    from mordred_hermes._private_fs import open_confidential_directory

    with open_confidential_directory(home / "memories") as d, d.transaction() as tx:
        tx.replace_bytes("MEMORY.md", seal(b"synthetic memory", key=key, name="MEMORY.md"))
    alias = home.with_name(home.name.upper())
    path = alias / "memories" / "memory.MD"
    with storage.windows_memory_session(alias, path=path) as session:
        assert session.read_plaintext(path.name) == "synthetic memory"
        session.write_entries(path.name, ["updated"], delimiter="\n§\n")
        session.create_backup("MEMORY.md.bak.42", "synthetic memory")
        assert len(session.inventory()) == 2
    data = (home / "memories" / "MEMORY.md").read_bytes()
    assert is_sealed(data)
    matches = unseal(data, key=key, name="MEMORY.md") == b"updated"
    assert matches, "native checked memory roundtrip failed"
    assert descriptor(home) == parent
    assert descriptor(home / "memories") == directory
    assert "ID;" not in descriptor(home / "memories" / "MEMORY.md")


@pytest.mark.parametrize("kind", ["acl", "hardlink", "junction"])
def test_native_unsafe_memory_refuses_unchanged(native_memory, tmp_path, kind):
    home, _ = native_memory
    path = home / "memories" / "MEMORY.md"
    if kind == "acl":
        powershell(
            path,
            """
            $u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
            $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
            $a.SetSecurityDescriptorSddlForm("O:${u}D:P(A;;FA;;;${u})(A;;FR;;;WD)");
            Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
            """,
        )
    elif kind == "hardlink":
        os.link(path, home / "memories" / "alias.md")
    else:
        alias = tmp_path / "memory-junction"
        subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(alias), str(home / "memories")],
            check=True,
            capture_output=True,
        )
        path = alias / "MEMORY.md"
    before = descriptor(home / "memories")
    with pytest.raises((PrivateFSError, RuntimeError)), storage.windows_memory_session(home, path=path, create=True):
        pass
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"synthetic memory"
    assert descriptor(home / "memories") == before


def test_native_memory_process_lock_serializes_unmanaged_write(native_memory):
    home, _ = native_memory
    script = """
import sys
from pathlib import Path
from mordred_hermes.keyvault._memory_storage import windows_memory_session
print('ready', flush=True)
with windows_memory_session(Path(sys.argv[1]), create=True) as session:
    session.write_entries('MEMORY.md', ['child'], delimiter='\\n§\\n')
print('done', flush=True)
"""
    from mordred_hermes._windows_runtime import scrubbed_environment

    env = scrubbed_environment(os.environ)
    env.update(HERMES_HOME=str(home), HERMES_SAFE_MODE="1", PYTHONUTF8="1")
    child = None
    try:
        with storage.windows_memory_session(home, create=True) as session:
            child = subprocess.Popen(
                [sys.executable, "-c", script, str(home)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert child.stdout.readline().strip() == "ready"
            assert session.read_plaintext("MEMORY.md") == "synthetic memory"
            assert child.poll() is None
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, "native memory child failed"
        assert stdout.strip() == "done"
        assert not stderr
        assert (home / "memories" / "MEMORY.md").read_bytes() == b"child"
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            child.communicate(timeout=5)
