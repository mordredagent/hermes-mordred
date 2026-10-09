"""Native inherited-ACL and junction cases through the privacy Windows audit factory.

No opener substitution: actual NTFS confidential/private admission, the real
token SID and the C7a/C2 Windows backends. The injected backend must never be
called because none of these paths is managed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.privacy_check import audit
from mordred_hermes.privacy_check._exceptions import AuditWriterRefused
from tests._keyvault_fakes import FakeBackend
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows ACLs and junctions")

VICTIM = b'{"event":"victim"}\n'


@pytest.fixture(autouse=True)
def forget_construction_refusals():
    from mordred_hermes.privacy_check import _windows_audit

    _windows_audit._forget_construction_refusals_for_tests()
    yield
    _windows_audit._forget_construction_refusals_for_tests()


def acl(path: Path) -> bytes:
    return subprocess.run(["icacls.exe", str(path)], check=True, capture_output=True).stdout


def junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)


def test_inherited_safe_home_gets_private_plaintext_audit_without_acl_repair(shared_home):
    backend = FakeBackend()
    home_acl = acl(shared_home)
    path = shared_home / "mordred" / "audit.log"
    writer = audit.make_audit_writer(path, keyvault_home=shared_home, backend=backend)
    assert writer.mode == "plaintext-degraded"
    writer.append({"event": "native"})
    assert path.read_bytes().count(b"\n") == 1
    assert acl(shared_home) == home_acl
    assert backend.calls == []


def test_broadened_active_acl_refuses_without_repair(shared_home):
    backend = FakeBackend()
    path = shared_home / "mordred" / "audit.log"
    writer = audit.make_audit_writer(path, keyvault_home=shared_home, backend=backend)
    writer.append({"event": "preserve"})
    subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before, descriptor = path.read_bytes(), acl(path)
    with pytest.raises(PrivateFSError) as append_error:
        writer.append({"event": "refuse"})
    assert append_error.value.reason == "unsafe"
    assert writer.refusal == "audit-unsafe"
    with pytest.raises(AuditWriterRefused) as construction:
        audit.make_audit_writer(path, keyvault_home=shared_home, backend=backend)
    assert construction.value.reason == "audit-unsafe"
    assert path.read_bytes() == before
    assert acl(path) == descriptor
    assert not list(path.parent.glob("audit.log.*"))
    assert backend.calls == []


def test_inherited_custom_directory_is_not_private_audit_storage(shared_home):
    backend = FakeBackend()
    custom = shared_home / "inherited-audit"
    custom.mkdir()
    (custom / "audit.log").write_bytes(VICTIM)
    descriptor = acl(custom)
    with pytest.raises(AuditWriterRefused) as error:
        audit.make_audit_writer(custom / "audit.log", keyvault_home=shared_home, backend=backend)
    assert error.value.reason == "audit-unsafe"
    assert acl(custom) == descriptor
    assert (custom / "audit.log").read_bytes() == VICTIM
    assert backend.calls == []


@pytest.mark.parametrize("where", ["active-file", "custom-directory"])
def test_junction_refuses_without_traversal(shared_home, tmp_path, where):
    backend = FakeBackend()
    target = tmp_path / "junction-target"
    with open_private_directory(target, create=True):
        pass
    (target / "audit.log").write_bytes(VICTIM)
    if where == "active-file":
        with open_private_directory(shared_home / "mordred", create=True):
            pass
        link = shared_home / "mordred" / "audit.log"
        path = link
    else:
        link = shared_home / "custom-audit"
        path = link / "audit.log"
    junction(link, target)
    with pytest.raises(AuditWriterRefused) as error:
        audit.make_audit_writer(path, keyvault_home=shared_home, backend=backend)
    assert error.value.reason == "audit-unsafe"
    assert (target / "audit.log").read_bytes() == VICTIM
    assert not list(target.glob("audit.log.*"))
    assert os.path.isjunction(link) if hasattr(os.path, "isjunction") else link.exists()
    assert backend.calls == []
