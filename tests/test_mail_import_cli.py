"""``hermes-mordred mail import|status``: dry run, gate refusal, store writes and content-free output."""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports import store as store_module
from mordred_hermes.imports.mail import stored_own_addresses
from mordred_hermes.imports.store import ImportRefused, ImportStore
from mordred_hermes.wizard import cli, mail_cli

FIXTURES = Path(__file__).parent / "fixtures" / "mail"
TAKEOUT = str(FIXTURES / "takeout_small.mbox")
BASE = ["mail", "import", "--mbox", TAKEOUT, "--own-address", "Owner@Example.com", "--account", "work"]
#: Subjects, names, bodies, message ids and addresses of the fixture that must never be printed or logged
#: (``owner.old@example.org`` is the one Sent-mail From address the report lists by design).
CANARIES = (
    "見積もりの件",
    "SUBJCANARY-A",
    "ランチ",
    "山田太郎",
    "佐々木 葵",
    "鈴木花子",
    "CANARY-BODY",
    "KM-4821",
    "taro@example.net",
    "hanako@example.org",
    "win@lottery.example",
    "owner@example.com",
    "mail.example.net",
    "You won",
)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(path))
    monkeypatch.setattr(mail_cli, "_home", lambda: path)
    return path


@pytest.fixture
def audits(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    monkeypatch.setattr(mail_cli, "_audit", lambda entry: entries.append(dict(entry)))
    return entries


@pytest.fixture
def store(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ImportStore:
    db = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    db.initialize(home)
    monkeypatch.setattr(store_module, "open_import_store", lambda _home: db)
    return db


@pytest.fixture
def no_store(monkeypatch: pytest.MonkeyPatch) -> None:
    def never(_home: Path) -> ImportStore:
        raise AssertionError("the store must not be opened")

    monkeypatch.setattr(store_module, "open_import_store", never)


def assert_no_canaries(*texts: str) -> None:
    joined = "\n".join(texts)
    assert [canary for canary in CANARIES if canary in joined] == []


def run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def committed(store: ImportStore) -> int:
    return int(store.status()["sources"].get("mail", {}).get("messages", 0))


# --- wiring ----------------------------------------------------------------------------------------


def test_parser_wires_mail_commands_and_keeps_source_order() -> None:
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    ns = parser.parse_args(
        ["mail", "import", "--eml", "a.eml", "--mbox", "b.mbox", "c.mbox", "--eml", "dir", "--account", "work"]
    )
    assert ns.func is cli._handle_mail
    assert ns.mail_sources == [("eml", "a.eml"), ("mbox", "b.mbox"), ("mbox", "c.mbox"), ("eml", "dir")]
    assert (ns.sent_label, ns.dry_run, ns.json, ns.preview_labels) == ("Sent", False, False, 0)
    assert parser.parse_args(["mail", "status", "--json"]).func is cli._handle_mail
    with pytest.raises(SystemExit):
        parser.parse_args([*BASE, "--preview-labels", "-1"])


def test_top_level_help_lists_mail(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "mail" in capsys.readouterr().out


# --- dry run ---------------------------------------------------------------------------------------


@pytest.mark.usefixtures("no_store")
def test_dry_run_prints_counts_only_and_never_opens_the_store(
    home: Path,
    audits: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    code, out, err = run([*BASE, "--dry-run"], capsys)
    assert code == 0, err
    assert "nothing was written" in out
    assert "parsed: 5" in out and "conversations: 2" in out
    assert "label_draft: 1" in out and "account_owner:gmail_label_sent: 2" in out
    assert "owner.old@example.org" in out  # a Sent From address missing from the own list
    assert_no_canaries(out, err, caplog.text)
    assert audits == []
    assert list(home.iterdir()) == []


@pytest.mark.usefixtures("no_store")
def test_dry_run_json_is_the_report(audits: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run([*BASE, "--dry-run", "--json"], capsys)
    assert code == 0, err
    report = json.loads(out)
    assert report["parsed"] == 5
    assert report["skipped"] == {"label_draft": 1, "label_spam": 1}
    assert report["threads_by_method"] == {"gmail_thrid": 2}
    assert report["sent_from_not_own"] == ["owner.old@example.org"]
    assert "written" not in report
    assert_no_canaries(out, err)


@pytest.mark.usefixtures("no_store")
def test_own_addresses_file_adds_addresses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    listing = tmp_path / "own.txt"
    listing.write_text("# my addresses\nOWNER.OLD@example.org  # old one\n\n", encoding="utf-8")
    code, out, err = run([*BASE, "--own-addresses-file", str(listing), "--dry-run", "--json"], capsys)
    assert code == 0, err
    assert json.loads(out)["sent_from_not_own"] == []


@pytest.mark.usefixtures("no_store")
def test_preview_prints_labels_and_head_lines_but_no_bodies(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run([*BASE, "--dry-run", "--preview-labels", "1"], capsys)
    assert code == 0, err
    preview = out.split("preview (first 1 conversations", 1)[1]
    assert "✉ " in preview
    assert "[Mail mail:work:a1@mail.example.net#a] speaker:" in preview
    assert "ランチ" not in preview  # only the first conversation
    assert "CANARY-BODY" not in out and "KM-4821" not in out
    assert_no_canaries(err)


# --- usage errors ----------------------------------------------------------------------------------


@pytest.mark.usefixtures("no_store")
@pytest.mark.parametrize("label", ["owner@example.com", "work:1", "my work", "", "-work", "x" * 65])
def test_account_must_be_an_opaque_label(label: str, capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["mail", "import", "--mbox", TAKEOUT, "--own-address", "a@example.com", f"--account={label}", "--dry-run"]
    code, out, err = run(argv, capsys)
    assert code == 2
    assert "--account" in err and out == ""
    assert "owner@example.com" not in err


@pytest.mark.usefixtures("no_store")
@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--own-address", "nobody"], "--own-address #2 is not a valid email address"),
        (["--own-address", "a b@example.com"], "--own-address #2 is not a valid email address"),
        (["--preview-labels", "3", "--json"], "--preview-labels cannot be combined with --json"),
        (["--sent-label", " "], "--sent-label"),
        (["--own-addresses-file", "/nonexistent/own.txt"], "--own-addresses-file cannot be read (not_found)"),
    ],
)
def test_bad_arguments_exit_2_without_echoing_values(
    extra: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run([*BASE, "--dry-run", *extra], capsys)
    assert code == 2
    assert message in err and out == ""
    assert "nobody" not in err and "a b@" not in err


@pytest.mark.usefixtures("no_store")
def test_sources_and_own_addresses_are_required(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(["mail", "import", "--account", "work", "--own-address", "a@example.com"], capsys)
    assert code == 2 and "--mbox PATH or --eml PATH" in err
    code, _, err = run(["mail", "import", "--mbox", TAKEOUT, "--account", "work", "--dry-run"], capsys)
    assert code == 2 and "at least one --own-address" in err
    missing = tmp_path / "secret-name.mbox"
    code, _, err = run(["mail", "import", "--mbox", str(missing), *BASE[4:], "--dry-run"], capsys)
    assert code == 2 and "mail source #1 (--mbox) cannot be read (not_found)" in err
    assert "secret-name" not in err and not missing.exists()
    code, _, err = run(["mail", "import", "--mbox", str(FIXTURES), *BASE[4:], "--dry-run"], capsys)
    assert code == 2 and "(not_regular_file)" in err


# --- gate refusal ----------------------------------------------------------------------------------


def test_refused_gate_exits_1_with_the_code_and_writes_nothing(
    home: Path, audits: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(_home: Path) -> ImportStore:
        raise ImportRefused("not_armed")

    monkeypatch.setattr(store_module, "open_import_store", refuse)
    code, out, err = run(BASE, capsys)
    assert code == 1
    assert out == ""
    assert err.strip() == "error: mail store refused (not_armed)"
    assert not (home / "plugin-data").exists()
    assert audits == []
    code, _, err = run(["mail", "status"], capsys)
    assert code == 1 and "(not_armed)" in err


def test_real_gate_refuses_an_unprotected_home(
    home: Path, audits: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    """No seam: the protection gate itself refuses a plain test home (unarmed / unsupported platform)."""
    code, out, err = run(BASE, capsys)
    assert code == 1 and out == ""
    assert "mail store refused (" in err
    assert not (home / "plugin-data").exists()
    assert audits == []


# --- real import -----------------------------------------------------------------------------------


def test_import_writes_commits_and_reimport_reports_duplicates(
    store: ImportStore,
    audits: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    code, out, err = run(BASE, capsys)
    assert code == 0, err
    assert "Mail import committed." in out
    assert "written:\n  inserted: 5\n  duplicates: 0\n  revised: 0\n  conflicts: 0" in out
    assert committed(store) == 5
    assert store.status()["runs"] == {"committed": 1}
    assert stored_own_addresses(store, "work") == {"owner@example.com"}
    [entry] = audits
    assert entry["event"] == "mail.import" and entry["decision"] == "committed" and entry["reason"] is None
    assert (entry["parsed"], entry["inserted"], entry["skipped"]) == (5, 5, 2)
    assert all(isinstance(value, int) for key, value in entry.items() if key not in {"event", "decision", "reason"})

    code, out2, err2 = run(BASE, capsys)
    assert code == 0, err2
    assert "written:\n  inserted: 0\n  duplicates: 5\n  revised: 0\n  conflicts: 0" in out2
    assert committed(store) == 5
    assert store.status()["runs"] == {"committed": 2}
    assert audits[1]["duplicates"] == 5
    assert_no_canaries(out, err, out2, err2, caplog.text, json.dumps(audits, ensure_ascii=False))


def test_stored_own_addresses_merge_and_status_shows_only_the_count(
    store: ImportStore, audits: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run([*BASE, "--own-address", "owner.old@example.org"], capsys)[0] == 0
    assert stored_own_addresses(store, "work") == {"owner@example.com", "owner.old@example.org"}
    # The recorded set is used in addition to the flags on the next real import.
    code, out, err = run([*BASE, "--json"], capsys)
    assert code == 0, err
    report = json.loads(out)
    assert report["sent_from_not_own"] == []
    assert report["written"] == {"inserted": 0, "duplicates": 5, "revised": 0, "conflicts": 0}
    assert stored_own_addresses(store, "work") == {"owner@example.com", "owner.old@example.org"}

    code, out, err = run(["mail", "status"], capsys)
    assert code == 0, err
    assert "work: 2 own address(es)" in out
    assert "messages: 5" in out and "committed=2" in out
    assert "@" not in out
    code, out, err = run(["mail", "status", "--json"], capsys)
    assert code == 0, err
    status = json.loads(out)
    assert status["accounts"] == {"work": {"own_addresses": 2}}
    assert status["mail"]["messages"] == 5
    assert status["last_run"]["counts"]["duplicates"] == 5
    assert "@" not in out


def test_status_of_an_empty_store(store: ImportStore, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(["mail", "status"], capsys)
    assert code == 0, err
    assert "accounts: none" in out and "runs: none" in out


def test_write_failure_fails_the_run_and_publishes_nothing(
    store: ImportStore,
    audits: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real = store.write_thread
    calls: list[int] = []

    def flaky(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("disk said CANARY-BODY-A1 taro@example.net")
        return real(*args, **kwargs)

    monkeypatch.setattr(store, "write_thread", flaky)
    code, out, err = run(BASE, capsys)
    assert code == 1 and out == ""
    assert err.strip() == "error: mail import failed (RuntimeError); nothing was published"
    assert committed(store) == 0
    assert store.contains(["mail:work:a1@mail.example.net"]) == set()
    assert store.status()["runs"] == {"failed": 1}
    assert stored_own_addresses(store, "work") == frozenset()
    [entry] = audits
    assert (entry["decision"], entry["error"], entry["inserted"]) == ("failed", "RuntimeError", 3)
    assert_no_canaries(out, err, json.dumps(audits, ensure_ascii=False))


@pytest.mark.parametrize(
    ("error", "code"),
    [(ImportRefused("busy"), "busy"), (RuntimeError("CANARY-BODY-A1 taro@example.net"), "RuntimeError")],
)
def test_store_failure_while_linking_fails_the_run_with_a_code(
    error: Exception,
    code: str,
    store: ImportStore,
    audits: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(store, "find_messages", broken)  # the store-backed linker cannot read: fail, never weaken
    exit_code, out, err = run(BASE, capsys)
    assert exit_code == 1 and out == ""
    assert err.strip() == f"error: mail import failed ({code}); nothing was published"
    assert committed(store) == 0
    assert audits[0]["error"] == code
    assert_no_canaries(err, json.dumps(audits, ensure_ascii=False))


def test_interrupt_fails_the_run_and_propagates(
    store: ImportStore,
    audits: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def interrupted(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(store, "write_thread", interrupted)
    assert cli.main(BASE) == 130  # dispatch turns the re-raised interrupt into "Aborted."
    assert store.status()["runs"] == {"failed": 1}
    assert audits[0]["error"] == "KeyboardInterrupt"
    capsys.readouterr()


def test_default_audit_writes_one_counts_only_entry(
    store: ImportStore, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(BASE, capsys)[0] == 0
    lines = (home / "mordred" / "audit.log").read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines]
    [entry] = [item for item in entries if item.get("event") == "mail.import"]
    assert entry["decision"] == "committed" and entry["inserted"] == 5
    assert_no_canaries("\n".join(lines))
    assert not (home / "plugin-data").exists()
