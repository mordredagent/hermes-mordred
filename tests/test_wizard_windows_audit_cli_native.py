"""Native NTFS cases for the Windows wizard audit CLI (C7b part 2).

Real confidential/private admission, the real token SID and the real ``win32``
platform decision (nothing patches ``_platform`` or the openers). Injected seams:
the CNG backend and C4 helper presence. Host-skipped off Windows; selected by
the scoped Windows CI job. Live CNG reuses the C5d audit live gate.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.keyvault import _seckey_helper
from mordred_hermes.keyvault import _windows_custody as custody
from mordred_hermes.privacy_check import audit as privacy_audit
from mordred_hermes.wizard import audit_cli
from tests._keyvault_fakes import FakeBackend
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual NTFS ACLs, hard links and junctions")

DAY = "2026-05-10"
VICTIM = b'{"event":"victim"}\n'


def acl(path: Path) -> bytes:
    return subprocess.run(["icacls.exe", str(path)], check=True, capture_output=True).stdout


def junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)


@pytest.fixture
def native(shared_home, monkeypatch):
    from mordred_hermes.privacy_check import _windows_audit

    home = shared_home
    backend = FakeBackend()
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: str(home.parent / "bin" / "winkey.exe"))
    monkeypatch.setattr(custody, "windows_backend", lambda: backend)
    active = home / "mordred" / "audit.log"
    monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: active)
    _windows_audit._forget_construction_refusals_for_tests()
    yield home, backend, active
    _windows_audit._forget_construction_refusals_for_tests()


def plaintext(home: Path, active: Path, backend, events: list[str]) -> None:
    writer = privacy_audit.make_audit_writer(active, keyvault_home=home, backend=backend)
    assert writer.mode == "plaintext-degraded"
    for event in events:
        writer.append({"event": event})


def test_native_plaintext_tail_and_grep_without_acl_repair(native, capsys):
    home, backend, active = native
    plaintext(home, active, backend, ["first", "second"])
    home_acl = acl(home)
    assert audit_cli.tail(n=1) == 0
    assert [json.loads(line)["event"] for line in capsys.readouterr().out.splitlines()] == ["second"]
    assert audit_cli.grep(pattern="first") == 0
    assert "first" in capsys.readouterr().out
    assert acl(home) == home_acl
    assert backend.calls == []


@pytest.mark.parametrize("kind", ["broadened-acl", "hardlink"])
def test_native_unsafe_active_file_refuses_without_repair(native, capsys, kind):
    home, backend, active = native
    plaintext(home, active, backend, ["kept"])
    if kind == "broadened-acl":
        subprocess.run(["icacls.exe", str(active), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    else:
        os.link(active, home / "audit-link")
    before, descriptor = active.read_bytes(), acl(active)
    assert audit_cli.tail(n=5) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "audit-unsafe" in captured.err and "Traceback" not in captured.err
    assert b"kept" not in captured.err.encode()
    assert active.read_bytes() == before
    assert acl(active) == descriptor


@pytest.mark.parametrize("verb", ["tail", "purge"])
def test_native_junctioned_custom_directory_refuses_without_traversal(native, monkeypatch, capsys, tmp_path, verb):
    home, backend, _ = native
    target = tmp_path / "junction-target"
    with open_private_directory(target, create=True):
        pass
    (target / "audit.log").write_bytes(VICTIM)
    (target / "audit.log.2026-01-01.gz").write_bytes(VICTIM)
    link = home / "custom-audit"
    junction(link, target)
    monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: link / "audit.log")
    rc = audit_cli.tail(n=5) if verb == "tail" else audit_cli.purge(before="2026-06-01")
    captured = capsys.readouterr()
    assert rc == 1
    assert "audit-unsafe" in captured.err and "victim" not in captured.out + captured.err
    assert (target / "audit.log").read_bytes() == VICTIM
    assert (target / "audit.log.2026-01-01.gz").read_bytes() == VICTIM
    assert backend.calls == []


def test_native_decrypt_and_purge_through_checked_custody(native, monkeypatch, capsys):
    from mordred_hermes.keyvault import windows_audit

    home, backend, active = native
    with custody.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_role("audit")
    writer = windows_audit.WindowsAuditProvider(home, backend=backend).writer(active, rotate_bytes=1)
    today = datetime.now(UTC).date().isoformat()
    for day, event in ((DAY, "a"), (DAY, "b"), (today, "c")):
        monkeypatch.setattr(windows_audit, "today_utc_date", lambda day=day: day)
        writer.append({"event": event})
    writer.close()
    manifest = (home / "mordred" / "windows-custody.json").read_bytes()
    assert audit_cli.decrypt(date=DAY, audit_dir=home / "mordred") == 0
    out = capsys.readouterr().out
    assert [json.loads(line)["event"] for line in out.splitlines() if line.startswith("{")] == ["a", "b"]
    assert audit_cli.purge(before="2026-06-01") == 0
    assert "2 rotated audit log file(s) purged." in capsys.readouterr().out
    assert sorted(p.name for p in (home / "mordred").glob("audit.log*")) == ["audit.log"]
    assert (home / "mordred" / "windows-custody.json").read_bytes() == manifest


def test_native_decrypt_without_helper_refuses_before_native_calls(native, monkeypatch, capsys):
    home, backend, _ = native
    with custody.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_role("audit")
    calls = list(backend.calls)
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    assert audit_cli.decrypt(date=DAY, audit_dir=home / "mordred") == 1
    captured = capsys.readouterr()
    assert "helper-missing" in captured.err and "keyvault enable-winkey" in captured.err
    assert backend.calls == calls
