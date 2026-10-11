"""Native ACL/hardlink/junction refusal through the Windows encrypted adapter."""

import os
import subprocess

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from tests.test_windows_encrypted_audit import (  # noqa: F401
    assert_no_cached_dek,
    checked_audit_boundary,
    custody_fixture,
    enrolled,
    provider,
)
from tests.test_windows_encrypted_audit import audit_fs as audit_fixture  # noqa: F401

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows ACLs, hardlinks and junctions")


@pytest.mark.parametrize("hostile", ["broad_acl", "hardlink", "junction"])
def test_encrypted_adapter_hostile_active_file_refuses_without_repair(fs, hostile):
    a, _, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    writer = provider(a, home, backend).writer(path)
    writer.append({"event": "preserve"})
    before = path.read_bytes()
    if hostile == "broad_acl":
        subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    elif hostile == "hardlink":
        os.link(path, path.with_name("alias"))
    else:
        path.unlink()
        target = home.parent / "junction-target"
        with open_private_directory(target, create=True):
            pass
        subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(path), str(target)], check=True, capture_output=True)
    acl = subprocess.run(["icacls.exe", str(path)], check=True, capture_output=True).stdout
    with pytest.raises(PrivateFSError) as append_error:
        writer.append({"event": "refuse"})
    with pytest.raises(PrivateFSError) as decrypt_error:
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)
    assert append_error.value.reason == decrypt_error.value.reason == "unsafe"
    assert_no_cached_dek(writer)
    assert path.exists()
    assert subprocess.run(["icacls.exe", str(path)], check=True, capture_output=True).stdout == acl
    if hostile != "junction":
        assert path.read_bytes() == before
    assert not list(path.parent.glob("audit.log.*.gz"))
    if hostile == "junction":
        # The definite refusal kept the owned active identity: once the hostile
        # junction is gone, the writer poisons instead of starting a fresh log.
        os.rmdir(path)
        with pytest.raises(PrivateFSError, match="audit_active_missing"):
            writer.append({"event": "recreate"})
        assert not path.exists()


def test_native_home_case_alias_uses_same_owned_role_and_default_loan(fs):
    a, _, home, backend, lease = enrolled(fs)
    alias = home.with_name(home.name.upper())
    path = alias / "MORDRED" / "audit.log"
    writer = provider(a, alias, backend).writer(path)
    assert writer.lease == lease
    writer.append({"event": "alias"})
    entries = a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)
    assert entries[0]["event"] == "alias"
