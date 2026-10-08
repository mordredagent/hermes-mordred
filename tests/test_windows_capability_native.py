"""Native NTFS capability predicates and flat role reset (C5e).

Real confidential/private admission, binary SID and physical home identity;
only the CNG boundary and the gateway inventory gate are injected. Host-skipped
off Windows; selected by the scoped Windows CI job.
"""

import os

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.keyvault import _memory_storage as storage
from mordred_hermes.keyvault import _seckey_helper
from mordred_hermes.keyvault import _windows_capability as cap
from mordred_hermes.keyvault import _windows_custody as custody
from tests._keyvault_fakes import FakeBackend
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual NTFS custody capability and reset")

SUPPORTED = ("memory_custody", "native_audit", "telegram_hardware")


@pytest.fixture
def native_custody(shared_home, monkeypatch):
    home = shared_home
    backend = FakeBackend()
    helper = str(home.parent / "bin" / "mordred-hermes-winkey.exe")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: helper)
    monkeypatch.setattr(storage, "windows_memory_runtime_admitted", lambda executable=None: True)
    monkeypatch.setattr(custody, "require_stopped_windows_gateways", lambda path: None)
    with custody.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        session.enroll_role("audit")
    return home, backend


def reasons(home):
    return {item.name: (item.available, item.reason) for item in cap.windows_capabilities(home)}


def opt_out(home):
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("memory-vault.optout", b"1\n")


def test_native_inherited_home_and_case_alias_report_same_checked_roles(native_custody, monkeypatch):
    home, backend = native_custody
    parent = descriptor(home)
    calls = list(backend.calls)

    def forbidden():
        raise AssertionError("capability constructed a native backend")

    monkeypatch.setattr(custody, "windows_backend", forbidden)
    expected = {
        "memory_custody": (True, "enrolled"),
        "native_audit": (True, "enrolled"),
        "telegram_hardware": (False, "not-enrolled"),
    }
    alias = home.with_name(home.name.upper())
    for target in (home, alias):
        result = reasons(target)
        assert {name: result[name] for name in SUPPORTED} == expected
        assert result["file_vault"] == (False, "excluded-on-windows")
    assert backend.calls == calls
    assert descriptor(home) == parent


def test_native_case_alias_memory_reset_preserves_audit_and_lock(native_custody):
    home, backend = native_custody
    alias = home.with_name(home.name.upper())
    opt_out(home)
    with custody.windows_custody_session(alias, backend=backend) as session:
        audit = session.lease("audit")
        memory = session.lease("memory")
        assert session.reset_role("memory").deleted == (memory.generation,)
        session.validate_lease(audit)
    assert memory.native_key_id not in backend._keys
    assert audit.native_key_id in backend._keys
    assert (home / "mordred").is_dir()
    assert (home / "mordred" / ".mordred-fs.lock").exists()


def test_native_copied_home_refuses_capabilities_and_reset(native_custody):
    home, backend = native_custody
    copied = home.parent / "copied home"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        for name in ("windows-custody.json", "memory-key.wrapped"):
            tx.create_bytes(name, (home / "mordred" / name).read_bytes())
        # Even an explicit opt-out cannot authorize deleting foreign custody.
        tx.create_bytes("memory-vault.optout", b"1\n")
    before = {name: (copied / "mordred" / name).read_bytes() for name in ("windows-custody.json", "memory-key.wrapped")}
    calls = list(backend.calls)
    result = reasons(copied)
    for name in SUPPORTED:
        assert result[name] == (False, "custody-broken")
    for role in ("memory", "audit"):
        with (
            pytest.raises(custody.CustodyError),
            custody.windows_custody_session(copied, backend=backend) as session,
        ):
            session.reset_role(role, erase_authorized=True)
    assert backend.calls == calls
    assert {name: (copied / "mordred" / name).read_bytes() for name in before} == before
