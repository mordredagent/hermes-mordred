"""Windows ``hermes-mordred audit {tail,grep,decrypt,purge}`` routing (C7b part 2).

Real checked custody, canonical coordination, C7a sessions, MRKW and MRAL; only
the native P-256 boundary, the token SID, the Windows optional openers and the
platform decision are injected (the C5d/C7b host pattern). POSIX symlinks, hard
links and broad modes stand in for NTFS junctions, hard links and broad ACLs;
``test_wizard_windows_audit_cli_native.py`` exercises the real objects.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import threading
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._audit_session import AuditSession
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import _seckey_helper, _storage, _windows_capability
from mordred_hermes.keyvault import log_encryption as mral
from mordred_hermes.privacy_check import audit as privacy_audit
from mordred_hermes.wizard import _windows_gates, audit_cli, cli
from tests._private_files import write_private
from tests.test_windows_privacy_audit import custody_fixture as custody_fixture
from tests.test_windows_privacy_audit import windows_fs as windows_fs

DAY = "2026-05-10"
SECRET = "do-not-echo-7f3a"
HELPER = Path("winkey-helper.exe")
#: audit_cli's POSIX descriptor helpers; none may run on Windows.
POSIX_HELPERS = (
    "_read_audit_path",
    "_read_regular_audit_entry",
    "_open_real_audit_directory",
    "_audit_entry_names",
    "_purge_rotated_entry",
    "_read_decrypt_targets",
    "_exclusive_audit_lock",
)
MUTATIONS = ("create", "append", "rename", "delete")
#: Broad modes and unprivileged symlinks only stand in for ACLs/junctions on POSIX;
#: hard links are real on NTFS. The native module covers the Windows objects.
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX mode/symlink stand-in; see the native module")


def today() -> str:
    return datetime.now(UTC).date().isoformat()


def tripwire(what: str):
    def refuse(*args, **kwargs):
        raise AssertionError(f"Windows audit CLI reached {what}")

    return refuse


@pytest.fixture
def win(fs, monkeypatch):
    """Windows routing on any host: the C5e predicates and the wizard seam say win32."""
    custody, _, home, backend = fs
    monkeypatch.setattr(_windows_capability, "_platform", lambda: "win32")
    monkeypatch.setattr(_windows_gates, "host_platform", lambda: "win32")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: HELPER)
    monkeypatch.setattr(custody, "windows_backend", lambda: backend)
    monkeypatch.setenv("HERMES_HOME", str(home))
    active = home / "mordred" / "audit.log"
    monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: active)
    for name in POSIX_HELPERS:
        monkeypatch.setattr(audit_cli, name, tripwire(f"the POSIX helper {name}"))
    return SimpleNamespace(custody=custody, home=home, backend=backend, mordred=home / "mordred", active=active)


def windows_cli():
    from mordred_hermes.wizard import _windows_audit_cli

    return _windows_audit_cli


def private_dir(path: Path) -> Path:
    with open_private_directory(path, create=True):
        pass
    return path


def private_write(path: Path, data: bytes) -> None:
    write_private(path, data)


def audit_files(directory: Path) -> dict[str, bytes]:
    if not directory.exists():
        return {}
    return {p.name: p.read_bytes() for p in sorted(directory.glob("audit.log*")) if not p.is_symlink()}


def custody_files(home: Path) -> dict[str, bytes]:
    mordred = home / "mordred"
    return {p.name: p.read_bytes() for p in sorted(mordred.glob("windows-*"))} if mordred.exists() else {}


def native_calls(backend) -> list[str]:
    return [op for op, _ in backend.calls]


def plaintext(env, events: list[str]) -> None:
    """A C7b part-1 explicit degraded log through the privacy factory."""
    writer = privacy_audit.make_audit_writer(env.active, keyvault_home=env.home, backend=env.backend)
    assert writer.mode == "plaintext-degraded"
    for event in events:
        writer.append({"event": event})


def enroll(env, *, retain_current: bool = False):
    with env.custody.windows_custody_session(env.home, create=True, backend=env.backend) as session:
        return session.enroll_role("audit", retain_current=retain_current)


def history(env, monkeypatch, plan: list[tuple[str, list[str]]], *, rotate_bytes: int = 1) -> None:
    """Real C5d MRAL writer; ``rotate_bytes=1`` rotates aside before every later append."""
    from mordred_hermes.keyvault import windows_audit

    writer = windows_audit.WindowsAuditProvider(env.home, backend=env.backend).writer(
        env.active, rotate_bytes=rotate_bytes
    )
    try:
        with monkeypatch.context() as patch:
            for day, events in plan:
                patch.setattr(windows_audit, "today_utc_date", lambda day=day: day)
                for event in events:
                    writer.append({"event": event})
    finally:
        writer.close()


def decrypted(out: str) -> list[str]:
    return [json.loads(line)["event"] for line in out.splitlines() if line.startswith("{")]


def headers(out: str) -> list[str]:
    return [line.split(" ")[1] for line in out.splitlines() if line.startswith("# ")]


def spy_decrypt(monkeypatch) -> list[tuple[str, dict[str, object]]]:
    from mordred_hermes.keyvault import windows_audit

    calls: list[tuple[str, dict[str, object]]] = []
    real = windows_audit.decrypt_windows_log_file

    def spy(path, **kwargs):
        calls.append((Path(path).name, dict(kwargs)))
        return real(path, **kwargs)

    monkeypatch.setattr(windows_audit, "decrypt_windows_log_file", spy)
    return calls


def forbid_posix_keyvault(monkeypatch) -> None:
    """The macOS/Linux decrypt route (Secure Enclave backend, ``_storage`` keyvault)."""
    monkeypatch.setattr(mral, "decrypt_log_file", tripwire("the POSIX keyvault decrypt"))
    monkeypatch.setattr(audit_cli, "resolve_backend", tripwire("the Secure Enclave backend resolver"))
    monkeypatch.setattr(_storage, "resolve_keyvault_dir", tripwire("the _storage keyvault"))
    monkeypatch.setattr(_storage, "keyvault_lifecycle_lock", tripwire("the _storage lifecycle lock"))


def forbid_mutations(monkeypatch) -> None:
    from mordred_hermes.keyvault import windows_audit

    for name in MUTATIONS:
        monkeypatch.setattr(AuditSession, name, tripwire(f"an audit-session {name}"))
    monkeypatch.setattr(windows_audit.WindowsEncryptedWriter, "append", tripwire("an encrypted append"))
    monkeypatch.setattr(windows_audit.WindowsEncryptedWriter, "append_in_custody", tripwire("an encrypted append"))


def refused(captured, reason: str) -> None:
    assert reason in captured.err
    assert "Traceback" not in captured.err
    assert SECRET not in captured.out + captured.err


# --- tail / grep ----------------------------------------------------------------------


def test_tail_and_grep_read_the_checked_plaintext_log_through_one_bounded_snapshot(win, monkeypatch, capsys):
    from mordred_hermes import _audit_session

    plaintext(win, ["alpha", "beta", "gamma"])
    reads: list[tuple[str, int]] = []
    real = _audit_session.read_audit_snapshot

    def spy(path, *, max_bytes):
        reads.append((Path(path).name, max_bytes))
        return real(path, max_bytes=max_bytes)

    monkeypatch.setattr(windows_cli(), "read_audit_snapshot", spy)
    assert audit_cli.tail(n=2) == 0
    out = capsys.readouterr().out
    assert [json.loads(line)["event"] for line in out.splitlines()] == ["beta", "gamma"]
    assert audit_cli.grep(pattern="alpha|gamma") == 0
    assert [json.loads(line)["event"] for line in capsys.readouterr().out.splitlines()] == ["alpha", "gamma"]
    assert audit_cli.grep(pattern="delta") == 1
    assert audit_cli.tail(n=0) == 0
    assert capsys.readouterr().out == ""
    # The existing C7a per-file bound; reading never needs custody or native I/O.
    assert reads == [("audit.log", 16 * 1024 * 1024)] * 4
    assert win.backend.calls == []


def test_tail_and_grep_report_a_missing_log(win, capsys):
    assert audit_cli.tail(n=5) == 1
    assert f"No audit log at {win.active}" in capsys.readouterr().err
    private_dir(win.mordred)
    assert audit_cli.grep(pattern=".") == 1
    assert f"No audit log at {win.active}" in capsys.readouterr().err
    assert not win.active.exists()


def test_mral_log_prints_the_decrypt_hint_without_echoing_ciphertext(win, monkeypatch, capsys):
    enroll(win)
    history(win, monkeypatch, [(today(), ["sealed"])])
    lines = win.active.read_bytes().splitlines()
    calls = list(win.backend.calls)
    for call in (lambda: audit_cli.tail(n=5), lambda: audit_cli.grep(pattern=".")):
        assert call() == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "appears encrypted" in captured.err
        assert "hermes-mordred audit decrypt --date YYYY-MM-DD" in captured.err
        assert not any(line.decode() in captured.err for line in lines)
    assert win.backend.calls == calls  # no custody, lease lookup or unwrap for a read


def hostile(env, kind: str, tmp_path: Path, monkeypatch) -> Path:
    """Arrange ``kind`` and return a path whose bytes must stay unchanged."""
    victim = b'{"event":"' + SECRET.encode() + b'"}\n'
    if kind == "junction-directory":
        target = private_dir(tmp_path / "junction-target")
        private_write(target / "audit.log", victim)
        link = env.home / "custom-audit"
        link.symlink_to(target, target_is_directory=True)
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: link / "audit.log")
        return target / "audit.log"
    private_dir(env.mordred)
    if kind == "broad-directory":
        private_write(env.active, victim)
        env.mordred.chmod(0o755)
        return env.active
    if kind == "junction-file":
        outside = private_dir(tmp_path / "outside")
        private_write(outside / "audit.log", victim)
        env.active.symlink_to(outside / "audit.log")
        return outside / "audit.log"
    private_write(env.active, victim)
    if kind == "broad-file":
        env.active.chmod(0o644)
    elif kind == "hardlink":
        os.link(env.active, env.mordred / "linked-copy")
    return env.active


UNSAFE = [
    pytest.param("broad-file", marks=POSIX_ONLY),
    pytest.param("broad-directory", marks=POSIX_ONLY),
    "hardlink",
    pytest.param("junction-file", marks=POSIX_ONLY),
    pytest.param("junction-directory", marks=POSIX_ONLY),
]


@pytest.mark.parametrize("kind", UNSAFE)
@pytest.mark.parametrize("verb", ["tail", "grep"])
def test_tail_and_grep_refuse_unsafe_state_without_echoing_bytes(win, monkeypatch, capsys, tmp_path, kind, verb):
    victim = hostile(win, kind, tmp_path, monkeypatch)
    before = victim.read_bytes()
    rc = audit_cli.tail(n=5) if verb == "tail" else audit_cli.grep(pattern=".")
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    refused(captured, "audit-unsafe")
    assert victim.read_bytes() == before
    assert win.backend.calls == []


def test_read_bound_refuses_instead_of_truncating(win, monkeypatch, capsys):
    plaintext(win, ["one", "two"])
    monkeypatch.setattr(windows_cli(), "ACTIVE_READ_LIMIT", 16)
    assert audit_cli.tail(n=1) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    refused(captured, "audit-unsafe")
    assert "audit_read_limit" in captured.err


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (PrivateFSError("io", "audit_snapshot", commit_state="uncertain"), "audit-uncertain"),
        (PrivateFSError("busy", "transaction"), "audit-unavailable"),
        (PrivateFSError("access_denied", "open"), "audit-unavailable"),
        (PrivateFSError("unsupported", "open"), "audit-unsafe"),
    ],
)
def test_read_failures_are_classified_refusals(win, monkeypatch, capsys, error, reason):
    plaintext(win, ["kept"])

    def fail(path, *, max_bytes):
        raise error

    monkeypatch.setattr(windows_cli(), "read_audit_snapshot", fail)
    assert audit_cli.grep(pattern="kept") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    refused(captured, reason)


def test_cli_tail_and_grep_route_on_windows(win, capsys):
    plaintext(win, ["via-cli"])
    assert cli.main(["audit", "tail", "-n", "1"]) == 0
    assert "via-cli" in capsys.readouterr().out
    assert cli.main(["audit", "grep", "via"]) == 0
    assert "via-cli" in capsys.readouterr().out


# --- decrypt --------------------------------------------------------------------------


def test_decrypt_prints_rotated_then_active_entries_oldest_first(win, monkeypatch, capsys):
    forbid_posix_keyvault(monkeypatch)
    enroll(win)
    events = [f"e{n:02d}" for n in range(12)]
    history(win, monkeypatch, [(DAY, events), (today(), ["t0", "t1"])])
    generated = native_calls(win.backend).count("generate")
    files = audit_files(win.mordred)
    calls = spy_decrypt(monkeypatch)

    assert audit_cli.decrypt(date=DAY, backend=win.backend) == 0
    out = capsys.readouterr().out
    # Numeric rotation order (.gz, .1.gz ... .11.gz), not alphabetical (.1, .10, .11, .2 ...).
    assert decrypted(out) == events
    expected = [f"audit.log.{DAY}.gz"] + [f"audit.log.{DAY}.{n}.gz" for n in range(1, 12)]
    assert headers(out) == expected
    assert [name for name, _ in calls] == expected
    for _, kwargs in calls:
        # Each file is snapshotted by C5d itself: no raw bytes are ever supplied.
        assert set(kwargs) == {"home", "audit_sink", "backend"}
        assert kwargs["home"] == win.home
        assert kwargs["backend"] is win.backend
        assert kwargs["audit_sink"] is audit_cli._stderr_unwrap_sink

    calls.clear()
    assert audit_cli.decrypt(date=today(), backend=win.backend) == 0
    out = capsys.readouterr().out
    assert decrypted(out) == ["t0", "t1"]
    assert headers(out) == [f"audit.log.{today()}.gz", "audit.log"]
    assert native_calls(win.backend).count("generate") == generated
    assert audit_files(win.mordred) == files


def test_decrypt_through_the_cli_uses_the_native_custody_backend(win, monkeypatch, capsys):
    forbid_posix_keyvault(monkeypatch)
    enroll(win)
    history(win, monkeypatch, [(DAY, ["first", "second"]), (today(), ["now"])])
    calls = spy_decrypt(monkeypatch)
    assert cli.main(["audit", "decrypt", "--date", DAY]) == 0
    captured = capsys.readouterr()
    assert decrypted(captured.out) == ["first", "second"]
    assert all(kwargs["backend"] is None for _, kwargs in calls)
    # The stderr sink surfaces each unwrap decision; it never appends to the log.
    assert "[audit] keyvault.unwrap_dek decision=allow" in captured.err


def copied_home(env, tmp_path: Path) -> Path:
    enroll(env)
    other = private_dir(tmp_path / "copied-home")
    private_dir(other / "mordred")
    private_write(other / "mordred" / "windows-custody.json", (env.mordred / "windows-custody.json").read_bytes())
    return other


@pytest.mark.parametrize(
    ("state", "reason", "remedy"),
    [
        ("not-enrolled", "not-enrolled", "keyvault native init --role audit"),
        ("helper-missing", "helper-missing", "keyvault enable-winkey"),
        ("copied", "custody-broken", "use the original profile directory"),
        pytest.param("unsafe", "custody-unsafe", "never repairs ACLs", marks=POSIX_ONLY),
        ("busy", "custody-uncertain", "let other Hermes/Mordred processes finish"),
    ],
)
def test_decrypt_refuses_before_any_native_call(win, monkeypatch, capsys, tmp_path, state, reason, remedy):
    forbid_posix_keyvault(monkeypatch)
    home = win.home
    private_dir(win.mordred)
    private_write(win.mordred / f"audit.log.{DAY}", b'{"fmt":"MRAL"}\nopaque\n')
    if state == "helper-missing":
        enroll(win)
        monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    elif state == "copied":
        home = copied_home(win, tmp_path)
        private_write(home / "mordred" / f"audit.log.{DAY}", b'{"fmt":"MRAL"}\nopaque\n')
    elif state == "unsafe":
        enroll(win)
        win.mordred.chmod(0o755)
    elif state == "busy":
        enroll(win)
    before_calls = list(win.backend.calls)
    before_files = audit_files(home / "mordred")
    before_custody = custody_files(home)
    monkeypatch.setattr(win.custody, "windows_backend", tripwire("the native backend"))
    calls = spy_decrypt(monkeypatch)

    holding, release = threading.Event(), threading.Event()

    def holder():
        with cio.canonical_session(cio.CanonicalPaths(home), scope="policy"):
            holding.set()
            release.wait(30)

    thread = threading.Thread(target=holder)
    if state == "busy":
        thread.start()
        assert holding.wait(30)
    try:
        rc = audit_cli.decrypt(date=DAY, audit_dir=home / "mordred")
    finally:
        release.set()
        if thread.is_alive():
            thread.join(30)
    if state == "unsafe":
        win.mordred.chmod(0o700)
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    refused(captured, reason)
    assert remedy in captured.err
    assert calls == []
    assert win.backend.calls == before_calls
    assert audit_files(home / "mordred") == before_files
    assert custody_files(home) == before_custody  # never enrolls or creates a manifest


def test_decrypt_never_writes_into_the_audit_log(win, monkeypatch, capsys):
    enroll(win)
    history(win, monkeypatch, [(DAY, ["a", "b", "c"]), (today(), ["d"])])
    files = audit_files(win.mordred)
    forbid_mutations(monkeypatch)
    assert audit_cli.decrypt(date=DAY) == 0
    assert audit_cli.decrypt(date=today()) == 0
    captured = capsys.readouterr()
    assert decrypted(captured.out) == ["a", "b", "c", "d"]
    assert captured.err.count("[audit] keyvault.unwrap_dek decision=allow") == 4
    assert audit_files(win.mordred) == files


@pytest.mark.parametrize(
    ("limit", "operation"), [("DECRYPT_TOTAL_LIMIT", "audit_total_limit"), ("MAX_ENTRIES", "list_limit")]
)
def test_decrypt_enumeration_is_bounded_before_any_native_call(win, monkeypatch, capsys, limit, operation):
    enroll(win)
    history(win, monkeypatch, [(DAY, ["a", "b", "c"]), (today(), ["d"])])
    monkeypatch.setattr(windows_cli(), limit, 2 if limit == "MAX_ENTRIES" else 64)
    before = list(win.backend.calls)
    calls = spy_decrypt(monkeypatch)
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    refused(captured, "audit-unsafe")
    assert operation in captured.err
    assert calls == []
    assert win.backend.calls == before


def test_decrypt_refuses_an_unsafe_target_before_any_native_call(win, monkeypatch, capsys, tmp_path):
    enroll(win)
    history(win, monkeypatch, [(DAY, ["a", "b"]), (today(), ["c"])])
    os.link(win.mordred / f"audit.log.{DAY}.1.gz", tmp_path / "second-link")
    before = list(win.backend.calls)
    calls = spy_decrypt(monkeypatch)
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    refused(captured, "audit-unsafe")
    assert calls == []
    assert win.backend.calls == before


def test_decrypt_reports_corrupt_and_foreign_files_then_continues(win, monkeypatch, capsys, tmp_path):
    enroll(win)
    history(win, monkeypatch, [(DAY, ["a", "b"]), (today(), ["c"])])
    # Plaintext history carries no MRAL header; a foreign selector is not owned here.
    private_write(win.mordred / f"audit.log.{DAY}.7", b'{"event":"' + SECRET.encode() + b'"}\n')
    header = json.loads((win.mordred / "audit.log").read_bytes().splitlines()[0])
    header["native_key_id"] = header["native_key_id"][:-4] + "beef"
    private_write(win.mordred / f"audit.log.{DAY}.8", json.dumps(header).encode() + b"\nAAAA\n")
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert decrypted(captured.out) == ["a", "b"]
    assert f"audit.log.{DAY}.7:" in captured.err
    assert f"audit.log.{DAY}.8: custody-broken" in captured.err
    refused(captured, "custody-broken")


def test_decrypt_missing_native_key_never_regenerates(win, monkeypatch, capsys):
    lease = enroll(win)
    history(win, monkeypatch, [(DAY, ["a"]), (today(), ["b"])])
    win.backend.delete_enclave_key(lease.native_key_id)
    generated = native_calls(win.backend).count("generate")
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "never regenerat" in captured.err
    assert "Secure Enclave" not in captured.err
    assert "keyvault initialised" not in captured.err
    assert "Traceback" not in captured.err
    assert native_calls(win.backend).count("generate") == generated


def test_decrypt_auth_denied_uses_windows_wording(win, monkeypatch, capsys):
    enroll(win)
    history(win, monkeypatch, [(DAY, ["a"]), (today(), ["b"])])
    win.backend.denied_reason = "auth_failed"
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "denied" in captured.err
    assert "Secure Enclave" not in captured.err
    assert "Traceback" not in captured.err


def test_decrypt_retained_generation_history_without_creating_keys(win, monkeypatch, capsys):
    enroll(win)
    history(win, monkeypatch, [(DAY, ["old-1", "old-2"]), ("2026-05-11", ["old-3"])])
    enroll(win, retain_current=True)
    history(win, monkeypatch, [("2026-05-12", ["new-1"]), (today(), ["new-2"])])
    generated = native_calls(win.backend).count("generate")
    assert audit_cli.decrypt(date=DAY) == 0
    assert decrypted(capsys.readouterr().out) == ["old-1", "old-2"]
    # A fresh C5d writer rotates the previous active file aside under its own
    # date, so 2026-05-12 holds a retained-generation file and a current one.
    assert audit_cli.decrypt(date="2026-05-12") == 0
    assert decrypted(capsys.readouterr().out) == ["old-3", "new-1"]
    assert native_calls(win.backend).count("generate") == generated


def test_decrypt_date_and_absence_exit_codes(win, monkeypatch, capsys):
    calls = spy_decrypt(monkeypatch)
    assert audit_cli.decrypt(date="2026/05/10") == 2
    assert "YYYY-MM-DD" in capsys.readouterr().err
    enroll(win)
    assert audit_cli.decrypt(date=DAY) == 1
    assert f"No audit log file found for {DAY} under {win.mordred}" in capsys.readouterr().err
    assert calls == []


# --- purge ----------------------------------------------------------------------------


def seed_purge(env) -> None:
    private_dir(env.mordred)
    for name in (
        "audit.log",
        "audit.log.2026-05-01.gz",
        "audit.log.2026-05-02",
        "audit.log.2026-05-02.1.gz",
        "audit.log.2026-06-01.gz",
        "audit.log.backup",
        "audit.log.2026-05-01.gz.bak",
        "notes.txt",
    ):
        private_write(env.mordred / name, name.encode())


def spy_deletes(monkeypatch) -> list[str]:
    deleted: list[str] = []
    real = AuditSession.delete

    def spy(self, name, *, expected_identity):
        deleted.append(name)
        return real(self, name, expected_identity=expected_identity)

    monkeypatch.setattr(AuditSession, "delete", spy)
    return deleted


def test_purge_deletes_only_enumerated_dated_files_through_checked_delete(win, monkeypatch, capsys):
    lease = enroll(win)
    seed_purge(win)
    custody = custody_files(win.home)
    calls = list(win.backend.calls)
    monkeypatch.setattr(shutil, "rmtree", tripwire("a recursive removal"))
    deleted = spy_deletes(monkeypatch)
    assert audit_cli.purge(before="2026-06-01") == 0
    out = capsys.readouterr().out
    gone = ["audit.log.2026-05-01.gz", "audit.log.2026-05-02", "audit.log.2026-05-02.1.gz"]
    assert sorted(deleted) == gone
    assert [line.removeprefix("purged ") for line in out.splitlines() if line.startswith("purged ")] == deleted
    assert "3 rotated audit log file(s) purged." in out
    assert sorted(audit_files(win.mordred)) == [
        "audit.log",
        "audit.log.2026-05-01.gz.bak",
        "audit.log.2026-06-01.gz",
        "audit.log.backup",
    ]
    assert (win.mordred / "notes.txt").exists()
    # The audit key is a separate C5e reset ceremony: custody is untouched.
    assert custody_files(win.home) == custody
    assert win.backend.calls == calls
    with win.custody.windows_custody_session(win.home, backend=win.backend) as session:
        assert session.role_status("audit").current == lease


@POSIX_ONLY
@pytest.mark.parametrize("kind", ["junction-directory", "broad-directory"])
def test_purge_refuses_unsafe_directory_without_deleting(win, monkeypatch, capsys, tmp_path, kind):
    if kind == "junction-directory":
        target = private_dir(tmp_path / "junction-target")
        private_write(target / "audit.log.2026-05-01.gz", b"victim")
        link = win.home / "custom-audit"
        link.symlink_to(target, target_is_directory=True)
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: link / "audit.log")
        watched = target
    else:
        seed_purge(win)
        win.mordred.chmod(0o755)
        watched = win.mordred
    before = audit_files(watched)
    assert audit_cli.purge(before="2026-06-01") == 1
    captured = capsys.readouterr()
    refused(captured, "audit-unsafe")
    assert "purged" not in captured.out
    assert audit_files(watched) == before


def test_purge_refuses_an_unsafe_entry_and_keeps_it(win, monkeypatch, capsys, tmp_path):
    seed_purge(win)
    os.link(win.mordred / "audit.log.2026-05-02", tmp_path / "outside-link")
    assert audit_cli.purge(before="2026-06-01") == 1
    captured = capsys.readouterr()
    refused(captured, "audit-unsafe")
    assert "audit.log.2026-05-02" in captured.err
    assert (win.mordred / "audit.log.2026-05-02").read_bytes() == b"audit.log.2026-05-02"
    assert (tmp_path / "outside-link").read_bytes() == b"audit.log.2026-05-02"
    assert not (win.mordred / "audit.log.2026-05-01.gz").exists()
    assert not (win.mordred / "audit.log.2026-05-02.1.gz").exists()


def test_purge_stops_at_an_uncertain_deletion(win, monkeypatch, capsys):
    seed_purge(win)
    real = AuditSession.delete
    attempts: list[str] = []

    def second_is_uncertain(self, name, *, expected_identity):
        attempts.append(name)
        if len(attempts) == 2:
            raise PrivateFSError("io", "delete_file", commit_state="uncertain")
        return real(self, name, expected_identity=expected_identity)

    monkeypatch.setattr(AuditSession, "delete", second_is_uncertain)
    assert audit_cli.purge(before="2026-06-01") == 1
    captured = capsys.readouterr()
    refused(captured, "audit-uncertain")
    # Nothing is attempted after the uncertain outcome; the third candidate stays.
    assert attempts == ["audit.log.2026-05-01.gz", "audit.log.2026-05-02"]
    assert sorted(audit_files(win.mordred))[:3] == ["audit.log", "audit.log.2026-05-01.gz.bak", "audit.log.2026-05-02"]
    assert (win.mordred / "audit.log.2026-05-02.1.gz").exists()
    assert "purged audit.log.2026-05-01.gz" in captured.out
    assert "1 file(s) had been purged when it stopped" in captured.err


def test_purge_cli_and_exit_codes(win, capsys):
    assert cli.main(["audit", "purge", "--before", "2026-06-01"]) == 2
    assert "--yes" in capsys.readouterr().err
    assert audit_cli.purge(before="06/01/2026") == 2
    assert "YYYY-MM-DD" in capsys.readouterr().err
    assert audit_cli.purge(before="2026-06-01") == 0
    assert "0 rotated audit log file(s) purged." in capsys.readouterr().out
    seed_purge(win)
    assert cli.main(["audit", "purge", "--before", "2026-05-02", "--yes"]) == 0
    assert "purged audit.log.2026-05-01.gz" in capsys.readouterr().out
    assert not (win.mordred / "audit.log.2026-05-01.gz").exists()


# --- platform boundary ----------------------------------------------------------------


@POSIX_ONLY
@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_posix_hosts_never_reach_the_windows_module(tmp_path, monkeypatch, capsys, platform):
    module = windows_cli()
    monkeypatch.setattr(_windows_gates, "host_platform", lambda: platform)
    for name in ("read_active_log", "decrypt", "purge"):
        monkeypatch.setattr(module, name, tripwire(f"the Windows {name}"))
    log = tmp_path / "audit.log"
    log.write_text('{"event":"posix"}\n', encoding="utf-8")
    assert audit_cli.tail(n=1, log_path=log) == 0
    assert audit_cli.grep(pattern="posix", log_path=log) == 0
    assert audit_cli.purge(before="2026-06-01", audit_dir=tmp_path) == 0
    assert audit_cli.decrypt(date=DAY, audit_dir=tmp_path) == 1
    assert "posix" in capsys.readouterr().out


def test_windows_module_imports_without_the_crypto_stack():
    script = textwrap.dedent(
        """
        import sys

        class _Blocker:
            BLOCKED = ("cryptography", "blake3", "argon2")

            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in self.BLOCKED:
                    raise ModuleNotFoundError(f"No module named {name!r} (blocked by test)")
                return None

        sys.meta_path.insert(0, _Blocker())
        import mordred_hermes.wizard._windows_audit_cli  # noqa: F401
        import mordred_hermes.wizard.audit_cli  # noqa: F401
        """
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
