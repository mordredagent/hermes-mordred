"""Truthful Windows capability predicates over checked custody state (C5e).

Portable: real checked files and MRKW crypto with an injected native P-256
boundary, principal and platform admission. Capability reads never construct a
native backend, unwrap, generate, delete or launch a subprocess.
"""

import dataclasses
import subprocess

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from tests.test_windows_custody import fs  # noqa: F401

SUPPORTED = ("memory_custody", "native_audit", "telegram_hardware")
EXCLUDED = ("file_vault", "env_config_workspace_seals", "recovery", "presence")


def capability_module():
    from mordred_hermes.keyvault import _windows_capability

    return _windows_capability


@pytest.fixture
def caps(fs, monkeypatch):  # noqa: F811
    c, storage, home, backend = fs
    from mordred_hermes.keyvault import _seckey_helper

    cap = capability_module()
    monkeypatch.setattr(cap, "_platform", lambda: "win32")
    helper = str(home.parent / "bin" / "mordred-hermes-winkey.exe")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: helper)
    monkeypatch.setattr(storage, "windows_memory_runtime_admitted", lambda executable=None: True)
    return cap, c, storage, home, backend


def forbid_native(monkeypatch, custody):
    """Fail if a capability read reaches native custody, unwrap or a subprocess."""
    from mordred_hermes.keyvault import wrap

    def tripwire(*args, **kwargs):
        raise AssertionError("capability read reached a forbidden native or subprocess operation")

    monkeypatch.setattr(custody, "windows_backend", tripwire)
    monkeypatch.setattr(wrap, "unwrap_dek", tripwire)
    monkeypatch.setattr(wrap, "wrap_dek", tripwire)
    monkeypatch.setattr(subprocess, "run", tripwire)
    monkeypatch.setattr(subprocess, "Popen", tripwire)


def reasons(result):
    return {item.name: (item.supported, item.available, item.reason) for item in result}


def assert_excluded(result):
    for name in EXCLUDED:
        assert reasons(result)[name] == (False, False, "excluded-on-windows")


def test_capability_shape_is_frozen_without_aggregate_ready_flag(caps, monkeypatch):
    cap, c, _, home, _ = caps
    forbid_native(monkeypatch, c)
    result = cap.windows_capabilities(home)
    assert tuple(item.name for item in result) == SUPPORTED + EXCLUDED
    assert [field.name for field in dataclasses.fields(cap.WindowsCapability)] == [
        "name",
        "supported",
        "available",
        "reason",
    ]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result[0].available = True
    assert not any("ready" in name.casefold() for name in dir(cap))
    assert_excluded(result)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_non_windows_platform_refuses_as_unsupported(caps, monkeypatch, platform):
    cap, c, _, home, _ = caps
    forbid_native(monkeypatch, c)
    monkeypatch.setattr(cap, "_platform", lambda: platform)
    for call in (
        lambda: cap.windows_capabilities(home),
        lambda: cap.windows_capability(home, "memory_custody"),
        lambda: cap.windows_capability(home, "file_vault"),
        lambda: cap.excluded_artifacts(home),
    ):
        with pytest.raises(PrivateFSError) as refused:
            call()
        assert refused.value.reason == "unsupported"
    assert not (home / "mordred").exists()


def test_absent_and_fresh_homes_are_supported_but_not_enrolled(caps, monkeypatch):
    cap, c, _, home, backend = caps
    forbid_native(monkeypatch, c)
    absent = home.parent / "absent"
    for target in (absent, home):
        result = reasons(cap.windows_capabilities(target))
        for name in SUPPORTED:
            assert result[name] == (True, False, "not-enrolled")
    assert not absent.exists()
    assert not (home / "mordred").exists()
    assert backend.calls == []


def test_managed_roles_are_available_from_checked_ownership_only(caps, monkeypatch):
    cap, c, _, home, backend = caps
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        session.enroll_role("audit")
        session.enroll_role("telegram")
    calls = list(backend.calls)
    forbid_native(monkeypatch, c)
    result = cap.windows_capabilities(home)
    for name in SUPPORTED:
        assert reasons(result)[name] == (True, True, "enrolled")
    assert_excluded(result)
    assert backend.calls == calls
    assert cap.windows_capability(home, "native_audit") == result[1]


def test_unmanaged_roles_stay_independent(caps, monkeypatch):
    cap, c, _, home, backend = caps
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_role("audit")
    forbid_native(monkeypatch, c)
    result = reasons(cap.windows_capabilities(home))
    assert result["native_audit"] == (True, True, "enrolled")
    assert result["memory_custody"] == (True, False, "not-enrolled")
    assert result["telegram_hardware"] == (True, False, "not-enrolled")


@pytest.mark.parametrize("failure", ["missing", "raises"])
def test_missing_or_uncertain_helper_is_never_available(caps, monkeypatch, failure):
    cap, c, _, home, backend = caps
    from mordred_hermes.keyvault import _seckey_helper

    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        session.enroll_role("audit")

    def raises():
        raise OSError("PATH lookup failed")

    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", (lambda: None) if failure == "missing" else raises)
    forbid_native(monkeypatch, c)
    expected = "helper-missing" if failure == "missing" else "helper-uncertain"
    result = reasons(cap.windows_capabilities(home))
    assert result["memory_custody"] == (True, False, expected)
    assert result["native_audit"] == (True, False, expected)
    assert result["telegram_hardware"] == (True, False, expected)


def test_memory_requires_structural_c4_runtime_admission(caps, monkeypatch):
    cap, c, storage, home, backend = caps
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        session.enroll_role("audit")
    monkeypatch.setattr(storage, "windows_memory_runtime_admitted", lambda executable=None: False)
    forbid_native(monkeypatch, c)
    result = reasons(cap.windows_capabilities(home))
    assert result["memory_custody"] == (True, False, "runtime-not-admitted")
    assert result["native_audit"] == (True, True, "enrolled")


def test_lost_memory_wrapper_is_broken_without_hiding_other_roles(caps, monkeypatch):
    cap, c, _, home, backend = caps
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        session.enroll_role("audit")
    (home / "mordred" / "memory-key.wrapped").unlink()
    forbid_native(monkeypatch, c)
    result = reasons(cap.windows_capabilities(home))
    assert result["memory_custody"] == (True, False, "custody-broken")
    assert result["native_audit"] == (True, True, "enrolled")


def test_retained_marker_without_ownership_is_broken_not_fresh(caps, monkeypatch):
    cap, c, _, home, _ = caps
    with open_private_directory(home / "mordred", create=True) as d, d.transaction() as tx:
        tx.create_bytes("memory-vault.marker", b"1\n")
    forbid_native(monkeypatch, c)
    result = reasons(cap.windows_capabilities(home))
    assert result["memory_custody"] == (True, False, "custody-broken")
    assert result["native_audit"] == (True, False, "not-enrolled")


def test_unresolved_journal_is_uncertain(caps, monkeypatch):
    cap, c, _, home, backend = caps

    def denied(*args, **kwargs):
        raise c.CustodyError("native unavailable")

    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    monkeypatch.setattr(backend, "generate_enclave_key", denied)
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, backend=backend) as session:
        session.enroll_role("telegram")
    journal = home / "mordred" / "windows-telegram.pending.json"
    before = journal.read_bytes()
    forbid_native(monkeypatch, c)
    result = reasons(cap.windows_capabilities(home))
    assert result["telegram_hardware"] == (True, False, "custody-uncertain")
    assert result["memory_custody"] == (True, True, "enrolled")
    assert journal.read_bytes() == before


def test_copied_home_is_broken_for_every_role(caps, monkeypatch):
    cap, c, _, home, backend = caps
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        session.enroll_role("audit")
    copied = home.parent / "copied"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        for name in ("windows-custody.json", "memory-key.wrapped"):
            tx.create_bytes(name, (home / "mordred" / name).read_bytes())
    forbid_native(monkeypatch, c)
    result = reasons(cap.windows_capabilities(copied))
    for name in SUPPORTED:
        assert result[name] == (True, False, "custody-broken")
    assert_excluded(cap.windows_capabilities(copied))


@pytest.mark.parametrize(
    "error,expected",
    [
        (PrivateFSError("unsafe", "ancestor_identity"), "custody-unsafe"),
        (PrivateFSError("access_denied", "open"), "custody-unsafe"),
        (PrivateFSError("io", "read", commit_state="uncertain"), "custody-uncertain"),
        (PrivateFSError("busy", "canonical_lock"), "custody-uncertain"),
        (cio.PolicyPendingError("pending policy publication"), "custody-uncertain"),
    ],
)
def test_unsafe_or_uncertain_storage_is_classified_never_available(caps, monkeypatch, error, expected):
    cap, c, _, home, backend = caps
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()

    def refuse(path):
        raise error

    monkeypatch.setattr(cio, "open_optional_confidential_directory", refuse)
    forbid_native(monkeypatch, c)
    result = cap.windows_capabilities(home)
    for name in SUPPORTED:
        assert reasons(result)[name] == (True, False, expected)
    assert_excluded(result)


def test_unclassified_failure_propagates_instead_of_reporting(caps, monkeypatch):
    cap, c, _, home, _ = caps

    def broken(path):
        raise RuntimeError("programming error")

    monkeypatch.setattr(cio, "open_optional_confidential_directory", broken)
    forbid_native(monkeypatch, c)
    with pytest.raises(RuntimeError, match="programming error"):
        cap.windows_capabilities(home)


def test_excluded_capability_query_reads_no_custody(caps, monkeypatch):
    cap, c, _, home, _ = caps

    def tripwire(*args, **kwargs):
        raise AssertionError("excluded capability touched custody")

    monkeypatch.setattr(c, "windows_custody_session", tripwire)
    monkeypatch.setattr(cio, "open_optional_confidential_directory", tripwire)
    forbid_native(monkeypatch, c)
    for name in EXCLUDED:
        assert cap.windows_capability(home, name) == cap.WindowsCapability(name, False, False, "excluded-on-windows")
    with pytest.raises(ValueError):
        cap.windows_capability(home, "windows_ready")
