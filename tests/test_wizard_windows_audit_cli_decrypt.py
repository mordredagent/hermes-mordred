"""Windows ``audit decrypt`` rules pinned in review round 2 (C7b part 2).

Same host pattern as ``test_wizard_windows_audit_cli.py`` (real custody, C7a
sessions and MRKW/MRAL; native boundary, SID, openers and platform injected):
the per-file stop/continue matrix, rotation between listing and decrypt, bound
remedies, plaintext guidance for an unenrolled profile, UTF-8 output on Windows
and the remaining absence/gate branches.
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

from mordred_hermes._audit_session import AuditSession
from mordred_hermes._config_io import PolicyPendingError
from mordred_hermes._private_fs import PrivateFSError
from mordred_hermes.keyvault import _windows_capability
from mordred_hermes.keyvault._exceptions import WrapAuthCancelled, WrapKeyNotFound, WrapNativeUnavailable
from mordred_hermes.keyvault._windows_profile import CustodyError
from mordred_hermes.keyvault.log_encryption import AuditLogDecryptError
from mordred_hermes.wizard import audit_cli
from tests.test_wizard_windows_audit_cli import (
    DAY,
    decrypted,
    enroll,
    history,
    plaintext,
    private_dir,
    private_write,
    seed_purge,
    spy_decrypt,
    today,
    windows_cli,
)
from tests.test_wizard_windows_audit_cli import custody_fixture as custody_fixture
from tests.test_wizard_windows_audit_cli import win as win
from tests.test_wizard_windows_audit_cli import windows_fs as windows_fs


def two_targets(env, monkeypatch) -> list[str]:
    """``DAY`` holds two files: ``.gz`` (``a``) then ``.1.gz`` (``b``)."""
    enroll(env)
    history(env, monkeypatch, [(DAY, ["a", "b"]), (today(), ["c"])])
    return [f"audit.log.{DAY}.gz", f"audit.log.{DAY}.1.gz"]


def fail_first(monkeypatch, error) -> list[str]:
    from mordred_hermes.keyvault import windows_audit

    calls: list[str] = []
    real = windows_audit.decrypt_windows_log_file

    def hook(path, **kwargs):
        calls.append(Path(path).name)
        if len(calls) == 1:
            raise error(Path(path))
        return real(path, **kwargs)

    monkeypatch.setattr(windows_audit, "decrypt_windows_log_file", hook)
    return calls


# --- stop / continue per failure -------------------------------------------------------

MATRIX = [
    ("custody-broken", lambda p: CustodyError("native selector is not owned"), False, "custody-broken"),
    ("corrupt", lambda p: AuditLogDecryptError(f"{p}: header does not match"), False, "header does not match"),
    ("vanished", lambda p: FileNotFoundError(p), False, "re-run"),
    ("auth-denied", lambda p: WrapAuthCancelled("auth_failed"), True, "denied the audit custody key"),
    ("key-missing", lambda p: WrapKeyNotFound("missing"), True, "never regenerates"),
    ("native-unavailable", lambda p: WrapNativeUnavailable("transient"), True, "native-unavailable"),
    ("policy-pending", lambda p: PolicyPendingError("pending"), True, "custody-uncertain"),
    ("storage-unsafe", lambda p: PrivateFSError("unsafe", "audit_snapshot_identity"), True, "audit-unsafe"),
    ("storage-busy", lambda p: PrivateFSError("busy", "transaction"), True, "audit-unavailable"),
    ("storage-uncertain", lambda p: PrivateFSError("io", "read", commit_state="uncertain"), True, "audit-uncertain"),
    ("invalid", lambda p: ValueError("invalid leaf"), True, "audit-invalid"),
]


@pytest.mark.parametrize(("case", "error", "stops", "wording"), MATRIX, ids=[row[0] for row in MATRIX])
def test_first_file_failure_stops_or_continues_as_documented(win, monkeypatch, capsys, case, error, stops, wording):
    names = two_targets(win, monkeypatch)
    calls = fail_first(monkeypatch, error)
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert wording in captured.err
    assert f"{names[0]}:" in captured.err or names[0] in captured.err
    assert "Traceback" not in captured.err
    if stops:
        assert calls == names[:1]
        assert decrypted(captured.out) == []
    else:
        assert calls == names
        assert decrypted(captured.out) == ["b"]


def test_unexpected_failure_propagates(win, monkeypatch):
    two_targets(win, monkeypatch)
    fail_first(monkeypatch, lambda p: RuntimeError("bug"))
    with pytest.raises(RuntimeError, match="bug"):
        audit_cli.decrypt(date=DAY)


# --- rotation between listing and decrypt -------------------------------------------------


def live_writer(env, rotate_bytes: int = 1):
    from mordred_hermes.keyvault import windows_audit

    return windows_audit.WindowsAuditProvider(env.home, backend=env.backend).writer(
        env.active, rotate_bytes=rotate_bytes
    )


def append_on(monkeypatch, writer, day: str, event: str) -> None:
    from mordred_hermes.keyvault import windows_audit

    with monkeypatch.context() as patch:
        patch.setattr(windows_audit, "today_utc_date", lambda: day)
        writer.append({"event": event})


def before_first_decrypt(monkeypatch, action) -> None:
    from mordred_hermes.keyvault import windows_audit

    real = windows_audit.decrypt_windows_log_file
    done: list[bool] = []

    def hook(path, **kwargs):
        if not done:
            done.append(True)
            action()
        return real(path, **kwargs)

    monkeypatch.setattr(windows_audit, "decrypt_windows_log_file", hook)


def test_day_change_rotation_during_decrypt_is_reported_not_silently_omitted(win, monkeypatch, capsys):
    enroll(win)
    writer = live_writer(win)
    append_on(monkeypatch, writer, DAY, "a")
    append_on(monkeypatch, writer, DAY, "b")  # DAY.gz holds a; the active log holds b
    before_first_decrypt(monkeypatch, lambda: append_on(monkeypatch, writer, "2026-05-11", "c"))
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert decrypted(captured.out) == ["a"]
    assert "changed during decrypt" in captured.err
    assert f"added audit.log.{DAY}.1.gz" in captured.err
    assert "re-run" in captured.err
    writer.close()
    assert audit_cli.decrypt(date=DAY) == 0
    assert decrypted(capsys.readouterr().out) == ["a", "b"]


def test_size_rotation_of_todays_active_log_is_reported(win, monkeypatch, capsys):
    enroll(win)
    writer = live_writer(win)
    now = today()
    append_on(monkeypatch, writer, now, "a")
    append_on(monkeypatch, writer, now, "b")  # TODAY.gz holds a; the active log holds b
    before_first_decrypt(monkeypatch, lambda: append_on(monkeypatch, writer, now, "c"))
    assert audit_cli.decrypt(date=now) == 1
    captured = capsys.readouterr()
    assert "b" not in decrypted(captured.out)
    assert f"added audit.log.{now}.1.gz" in captured.err
    assert "replaced audit.log" in captured.err
    assert "re-run" in captured.err
    writer.close()
    assert audit_cli.decrypt(date=now) == 0
    assert decrypted(capsys.readouterr().out) == ["a", "b", "c"]


def test_appends_without_rotation_are_not_a_change(win, monkeypatch, capsys):
    enroll(win)
    writer = live_writer(win, rotate_bytes=10 * 1024 * 1024)
    now = today()
    append_on(monkeypatch, writer, now, "a")
    before_first_decrypt(monkeypatch, lambda: append_on(monkeypatch, writer, now, "b"))
    assert audit_cli.decrypt(date=now) == 0
    captured = capsys.readouterr()
    assert decrypted(captured.out) == ["a", "b"]
    assert "changed during decrypt" not in captured.err
    writer.close()


# --- bound remedies ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("limit", "value", "bound"),
    [("DECRYPT_TOTAL_LIMIT", 64, "64-byte decrypt bound"), ("MAX_ENTRIES", 2, "more than 2 entries")],
)
def test_bound_refusals_name_the_bound_and_the_workaround(win, monkeypatch, capsys, limit, value, bound):
    two_targets(win, monkeypatch)
    monkeypatch.setattr(windows_cli(), limit, value)
    calls = spy_decrypt(monkeypatch)
    assert audit_cli.decrypt(date=DAY) == 1
    err = capsys.readouterr().err
    assert bound in err
    assert "out of the audit directory by hand" in err
    assert "fix it by hand" not in err
    assert calls == []


def test_read_bound_names_the_bound_and_waits_for_rotation(win, monkeypatch, capsys):
    plaintext(win, ["one", "two"])
    monkeypatch.setattr(windows_cli(), "ACTIVE_READ_LIMIT", 16)
    assert audit_cli.tail(n=1) == 1
    err = capsys.readouterr().err
    assert "16-byte read bound" in err
    assert "rotates" in err
    assert "fix it by hand" not in err


# --- unenrolled guidance -------------------------------------------------------------------


def test_not_enrolled_with_a_plaintext_log_points_to_tail_and_grep(win, monkeypatch, capsys):
    plaintext(win, ["plain"])
    calls = spy_decrypt(monkeypatch)
    assert audit_cli.decrypt(date=today()) == 1
    err = capsys.readouterr().err
    assert "not-enrolled" in err
    assert "plaintext" in err
    assert "hermes-mordred audit tail" in err and "hermes-mordred audit grep" in err
    assert "keyvault native init" not in err
    assert calls == []
    assert win.backend.calls == []


def test_not_enrolled_with_an_mral_log_keeps_the_enroll_remedy(win, monkeypatch, capsys):
    private_dir(win.mordred)
    private_write(win.active, b'{"fmt":"MRAL"}\nopaque\n')
    assert audit_cli.decrypt(date=today()) == 1
    err = capsys.readouterr().err
    assert "keyvault native init --role audit" in err
    assert "audit tail" not in err


# --- UTF-8 output on Windows ---------------------------------------------------------------


def test_decrypted_entries_are_written_as_utf8_under_a_legacy_code_page(win, monkeypatch, capsys):
    from mordred_hermes.keyvault import windows_audit

    enroll(win)
    writer = windows_audit.WindowsAuditProvider(win.home, backend=win.backend).writer(win.active)
    with monkeypatch.context() as patch:
        patch.setattr(windows_audit, "today_utc_date", lambda: today())
        writer.append({"event": "監査 — ✓"})
    writer.close()
    raw = io.BytesIO()
    legacy = io.TextIOWrapper(raw, encoding="cp932", errors="strict", newline="\n")
    with pytest.raises(UnicodeEncodeError):
        legacy.write("—")
    monkeypatch.setattr(sys, "stdout", legacy)
    assert audit_cli.decrypt(date=today()) == 0
    legacy.flush()
    text = raw.getvalue().decode("utf-8")
    assert "# audit.log — 1 entry" in text
    assert "監査 — ✓" in text
    assert legacy.encoding == "cp932", "the stream encoding is restored after the command"


# --- absence and gate branches --------------------------------------------------------------


def test_missing_ancestor_reads_as_no_log(win, monkeypatch, capsys):
    def missing(path, *, max_bytes):
        raise PrivateFSError("missing", "open", native_code=3)

    monkeypatch.setattr(windows_cli(), "read_audit_snapshot", missing)
    assert audit_cli.tail(n=1) == 1
    assert f"No audit log at {win.active}" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("error", "wording"),
    [
        (ValueError("relative"), "not a valid absolute Windows path"),
        (PrivateFSError("unsafe", "home"), "audit custody could not be read (custody-unsafe)"),
        (CustodyError("copied"), "audit custody could not be read (custody-broken)"),
    ],
)
def test_capability_read_failures_refuse(win, monkeypatch, capsys, error, wording):
    def fail(home, name):
        raise error

    monkeypatch.setattr(_windows_capability, "windows_capability", fail)
    calls = spy_decrypt(monkeypatch)
    assert audit_cli.decrypt(date=DAY) == 1
    err = capsys.readouterr().err
    assert wording in err and "Traceback" not in err
    assert calls == []


@pytest.mark.parametrize(
    ("error", "wording"),
    [
        (PrivateFSError("missing", "open", native_code=3), f"No audit log file found for {DAY}"),
        (ValueError("invalid leaf"), "audit-invalid"),
    ],
)
def test_listing_absence_and_invalid_paths(win, monkeypatch, capsys, error, wording):
    enroll(win)

    def fail(directory, target):
        raise error

    monkeypatch.setattr(windows_cli(), "decrypt_targets", fail)
    assert audit_cli.decrypt(date=DAY) == 1
    assert wording in capsys.readouterr().err


def test_purge_skips_entries_that_vanish_after_listing(win, monkeypatch, capsys):
    seed_purge(win)
    real = AuditSession.stat

    def racing(self, name):
        if name == "audit.log.2026-05-01.gz":
            return None
        if name == "audit.log.2026-05-02":
            raise PrivateFSError("missing", "stat", native_code=2)
        return real(self, name)

    monkeypatch.setattr(AuditSession, "stat", racing)
    assert audit_cli.purge(before="2026-06-01") == 0
    out = capsys.readouterr().out
    assert "purged audit.log.2026-05-02.1.gz" in out
    assert "1 rotated audit log file(s) purged." in out


@pytest.mark.parametrize(
    ("error", "rc", "wording"),
    [
        (PrivateFSError("missing", "open_directory", native_code=3), 0, "0 rotated audit log file(s) purged."),
        (ValueError("invalid leaf"), 1, "audit-invalid"),
    ],
)
def test_purge_session_absence_and_invalid_paths(win, monkeypatch, capsys, error, rc, wording):
    @contextlib.contextmanager
    def fail(path, **kwargs):
        raise error
        yield  # pragma: no cover

    monkeypatch.setattr(windows_cli(), "audit_session", fail)
    assert audit_cli.purge(before="2026-06-01") == rc
    captured = capsys.readouterr()
    assert wording in captured.out + captured.err


def test_invalid_read_path_is_classified(win, monkeypatch, capsys):
    def invalid(path, *, max_bytes):
        raise ValueError("invalid leaf")

    monkeypatch.setattr(windows_cli(), "read_audit_snapshot", invalid)
    assert audit_cli.grep(pattern=".") == 1
    assert "audit-invalid" in capsys.readouterr().err


def test_unreadable_active_log_keeps_the_enroll_remedy(win, monkeypatch, capsys):
    plaintext(win, ["plain"])

    @contextlib.contextmanager
    def unsafe(path, **kwargs):
        raise PrivateFSError("unsafe", "validate_object")
        yield  # pragma: no cover

    monkeypatch.setattr(windows_cli(), "audit_session", unsafe)
    assert audit_cli.decrypt(date=today()) == 1
    assert "keyvault native init --role audit" in capsys.readouterr().err


def test_a_target_vanishing_between_listing_and_stat_is_skipped(win, monkeypatch, capsys):
    names = two_targets(win, monkeypatch)
    real = AuditSession.stat
    monkeypatch.setattr(AuditSession, "stat", lambda self, name: None if name == names[0] else real(self, name))
    assert audit_cli.decrypt(date=DAY) == 0
    assert decrypted(capsys.readouterr().out) == ["b"]


@pytest.mark.parametrize(
    ("error", "wording"),
    [
        (PrivateFSError("unsafe", "list_limit"), "could not be re-checked"),
        (PrivateFSError("missing", "open", native_code=3), f"removed audit.log.{DAY}.gz"),
    ],
)
def test_failed_or_empty_relisting_is_reported(win, monkeypatch, capsys, error, wording):
    two_targets(win, monkeypatch)
    module = windows_cli()
    real = module.decrypt_targets
    listings: list[int] = []

    def relist(directory, target):
        listings.append(1)
        if len(listings) == 2:
            raise error
        return real(directory, target)

    monkeypatch.setattr(module, "decrypt_targets", relist)
    assert audit_cli.decrypt(date=DAY) == 1
    captured = capsys.readouterr()
    assert decrypted(captured.out) == ["a", "b"]
    assert wording in captured.err and "re-run" in captured.err


def test_utf8_scope_leaves_unknown_or_fixed_streams_alone(monkeypatch):
    module = windows_cli()
    assert module._is_utf8("no-such-codec") is False

    class Fixed:
        encoding = "cp932"

    monkeypatch.setattr(sys, "stdout", Fixed())
    with module._utf8_stdout():
        pass
    assert sys.stdout.encoding == "cp932"
