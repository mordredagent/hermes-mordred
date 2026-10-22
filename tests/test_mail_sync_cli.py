"""``hermes-mordred mail setup|fetch|forget|status`` for IMAP sync: prompts, sealing, counts-only output."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports.mail.imap_sync import RESULT_FIELDS
from mordred_hermes.imports.store import ImportRefused, ImportStore
from mordred_hermes.wizard import cli, mail_cli, mail_sync_cli
from tests._fake_imap import FakeImapServer, FakeMailbox
from tests._mail_sync_helpers import (
    CANARIES,
    PASSWORD,
    FakeSecrets,
    gmail_creds,
    gmail_server,
    make_env,
    make_store,
    rows,
)
from tests.test_mail_secrets import FakeEnclave, sealed_store


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(path))
    monkeypatch.setattr(mail_cli, "_home", lambda: path)
    monkeypatch.setattr(mail_sync_cli, "_home", lambda: path)
    monkeypatch.setattr(mail_sync_cli, "_platform", lambda: "darwin")
    return path


@pytest.fixture
def store(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> ImportStore:
    db = make_store(tmp_path, home)
    monkeypatch.setattr(mail_cli, "_open_store", lambda _home: db)
    monkeypatch.setattr(mail_sync_cli, "_open_store", lambda _home: db)
    return db


def run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def assert_no_canaries(*texts: str) -> None:
    joined = "\n".join(texts)
    assert [canary for canary in (*CANARIES, PASSWORD) if canary in joined] == []


# --- setup ----------------------------------------------------------------------------------------


@pytest.fixture
def setup_env(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    from tests._platform_test_helpers import require_posix_tee

    require_posix_tee()
    enclave = FakeEnclave()
    secret_store = sealed_store(tmp_path / "sealed", enclave)
    answers: list[str] = []
    prompts: list[str] = []
    state: dict[str, Any] = {"enclave": enclave, "store": secret_store, "answers": answers, "prompts": prompts}

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return answers.pop(0)

    monkeypatch.setattr(mail_sync_cli, "_isatty", lambda: True)
    monkeypatch.setattr(mail_sync_cli, "_input", fake_input)
    monkeypatch.setattr(mail_sync_cli, "_secret", lambda _prompt: PASSWORD)
    monkeypatch.setattr(mail_sync_cli, "_secret_store", lambda: secret_store)
    return state


def use_server(monkeypatch: pytest.MonkeyPatch, server: FakeImapServer) -> list[tuple[str, int]]:
    seen: list[tuple[str, int]] = []

    def connect(host: str, port: int) -> Any:
        seen.append((host, port))
        return server.session()

    monkeypatch.setattr(mail_sync_cli, "_connect", connect)
    return seen


def test_setup_gmail_seals_all_mail_found_by_special_use(
    setup_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    server = gmail_server()
    seen = use_server(monkeypatch, server)
    setup_env["answers"].extend(["owner@example.com", "old.me@example.org"])
    code, out, err = run(["mail", "setup", "--imap-host", "imap.example.com", "--account", "work"], capsys)
    assert code == 0, err
    assert seen == [("imap.example.com", 993)]
    creds = setup_env["store"].load()
    assert (creds.account, creds.gmail, creds.mailboxes) == ("work", True, {"all": "[Gmail]/All Mail"})
    assert creds.own_addresses == ("old.me@example.org", "owner@example.com")
    assert creds.app_password == PASSWORD
    assert "work" in out and "Gmail" in out
    assert_no_canaries(out, err)
    assert server.violations == [] and "LOGOUT" in server.verbs


def test_setup_generic_server_uses_special_use_sent(
    setup_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(1), "Sent Items": FakeMailbox(2, attributes=("\\Sent",))})
    use_server(monkeypatch, server)
    setup_env["answers"].extend(["owner@example.com", "imap.example.com", ""])
    code, _out, err = run(["mail", "setup", "--no-touch-id"], capsys)
    assert code == 0, err
    creds = setup_env["store"].load()
    assert (creds.gmail, creds.mailboxes, creds.account) == (False, {"inbox": "INBOX", "sent": "Sent Items"}, "mail")
    assert setup_env["store"].flags()["touch_id"] is False


def test_setup_asks_for_the_sent_folder_when_none_is_marked(
    setup_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(1), "Gesendet": FakeMailbox(2), "Archiv": FakeMailbox(3)})
    use_server(monkeypatch, server)
    setup_env["answers"].extend(["owner@example.com", "imap.example.com", "", "2"])
    code, out, err = run(["mail", "setup"], capsys)
    assert code == 0, err
    assert "1. INBOX" in out and "2. Gesendet" in out
    assert setup_env["store"].load().mailboxes == {"inbox": "INBOX", "sent": "Gesendet"}


def test_setup_refuses_without_a_tty(
    setup_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mail_sync_cli, "_isatty", lambda: False)
    code, out, err = run(["mail", "setup"], capsys)
    assert code == 1 and "tty_required" in err and out == ""
    assert setup_env["prompts"] == [] and setup_env["store"].flags() is None


@pytest.mark.parametrize(
    "argv", [["--account", "Work"], ["--account", "a@b"], ["--imap-port", "0"], ["--imap-port", "143"]]
)
def test_setup_bad_arguments_exit_2(
    setup_env: dict[str, Any], argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    try:
        code = cli.main(["mail", "setup", *argv])
    except SystemExit as exc:
        code = int(exc.code or 0)
    capsys.readouterr()
    assert code == 2 and setup_env["store"].flags() is None


def test_setup_with_a_wrong_password_seals_nothing(
    setup_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    server = gmail_server()
    server.password = "another"
    use_server(monkeypatch, server)
    setup_env["answers"].extend(["owner@example.com", ""])
    code, out, err = run(["mail", "setup", "--imap-host", "imap.example.com"], capsys)
    assert code == 1 and "imap_auth_failed" in err
    assert setup_env["store"].flags() is None
    assert_no_canaries(out, err)


def test_setup_refuses_other_platforms(
    setup_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mail_sync_cli, "_platform", lambda: "linux")
    code, _out, err = run(["mail", "setup"], capsys)
    assert code == 1 and "unsupported_platform" in err and setup_env["prompts"] == []


# --- fetch ----------------------------------------------------------------------------------------


@pytest.fixture
def fetch_env(home: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    server = gmail_server()
    audits: list[Any] = []
    secrets = FakeSecrets(gmail_creds())
    env = make_env(home, store, server, secrets, audits=audits)
    monkeypatch.setattr(mail_sync_cli, "_fetch_env", lambda: env)
    return {"server": server, "audits": audits, "secrets": secrets, "env": env}


def test_fetch_json_is_exactly_the_fixed_serializer(
    fetch_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    code, out, err = run(["mail", "fetch", "--json"], capsys)
    assert code == 0, err
    data = json.loads(out)
    assert set(data) == RESULT_FIELDS
    assert (data["inserted"], data["gmail"], data["error"]) == (3, True, None)
    assert_no_canaries(out, err, caplog.text, json.dumps(fetch_env["audits"]))


def test_fetch_text_prints_counts_and_cursors(fetch_env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(["mail", "fetch"], capsys)
    assert code == 0, err
    assert "Mail fetch complete." in out and "inserted: 3" in out and "cursor all: uid 4" in out
    assert_no_canaries(out, err)


def test_fetch_dry_run_writes_nothing(
    fetch_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(["mail", "fetch", "--dry-run"], capsys)
    assert code == 0, err
    assert "nothing was written" in out
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]
    assert rows(store, "SELECT count(*) FROM import_runs") == [(0,)]
    assert store.meta_items("mail_imap.") == {}
    assert fetch_env["audits"] == []


def test_fetch_errors_exit_1_with_the_code(
    fetch_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fetch_env["server"].password = "changed"
    code, out, err = run(["mail", "fetch", "--json"], capsys)
    assert code == 1 and "mail fetch failed (imap_auth_failed)" in err
    assert json.loads(out)["error"] == "imap_auth_failed"


@pytest.mark.parametrize(
    "argv", [["--max", "0"], ["--max", "2001"], ["--max", "x"], ["--since", "2026-13-01"], ["--mailbox", "trash"]]
)
def test_fetch_bad_arguments_exit_2(
    fetch_env: dict[str, Any], argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    try:
        code = cli.main(["mail", "fetch", *argv])
    except SystemExit as exc:
        code = int(exc.code or 0)
    capsys.readouterr()
    assert code == 2
    assert fetch_env["server"].commands == []


def test_fetch_passes_max_mailbox_and_since(
    monkeypatch: pytest.MonkeyPatch, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from mordred_hermes.imports.mail import imap_sync

    seen: list[Any] = []

    def fake_run(options: Any, env: Any) -> Any:
        seen.append(options)
        return imap_sync.FetchResult()

    monkeypatch.setattr(mail_sync_cli, "_fetch_env", lambda: None)
    monkeypatch.setattr(imap_sync, "run_fetch", fake_run)
    monkeypatch.setattr(mail_sync_cli, "_print_cursors", lambda _env: None)
    assert run(["mail", "fetch", "--max", "5", "--mailbox", "sent", "--since", "2026-09-01"], capsys)[0] == 0
    [options] = seen
    assert (options.max_messages, options.roles, str(options.since), options.budget_s, options.via) == (
        5,
        ("sent",),
        "2026-09-01",
        600.0,
        "cli",
    )


# --- status ---------------------------------------------------------------------------------------


def test_status_shows_the_imap_state_but_never_the_address(
    fetch_env: dict[str, Any], store: ImportStore, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(["mail", "fetch"], capsys)[0] == 0
    monkeypatch.setattr(mail_cli, "_imap_flags", lambda: fetch_env["secrets"].flags())
    code, out, err = run(["mail", "status"], capsys)
    assert code == 0, err
    assert "imap sync: account mail (Gmail All Mail" in out and "all: uid 4" in out and "last fetch:" in out
    assert "@" not in out
    code, out, _err = run(["mail", "status", "--json"], capsys)
    imap = json.loads(out)["imap"]
    assert (imap["account"], imap["gmail"], imap["scope"]) == ("mail", True, ["all"])
    assert imap["cursors"]["all"]["forward"]["uid"] == 4
    assert imap["last_fetch"]["error"] is None
    assert "@" not in out


def test_status_without_imap_setup(store: ImportStore, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(["mail", "status"], capsys)
    assert code == 0, err
    assert "imap sync: not set up" in out


# --- forget ---------------------------------------------------------------------------------------


@pytest.fixture
def forget_env(
    home: Path, store: ImportStore, fetch_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    assert fetch_env["env"] is not None
    from mordred_hermes.imports.mail.imap_sync import FetchOptions, run_fetch

    assert run_fetch(FetchOptions(), fetch_env["env"]).inserted == 3

    class Forgettable(FakeSecrets):
        forgotten = 0

        def forget(self) -> None:
            Forgettable.forgotten += 1
            self.creds = None

    secrets = Forgettable(gmail_creds())
    monkeypatch.setattr(mail_sync_cli, "_secret_store", lambda: secrets)
    return {"secrets": secrets}


def test_forget_requires_yes(forget_env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    code, _out, err = run(["mail", "forget"], capsys)
    assert code == 2 and "--yes" in err
    assert forget_env["secrets"].creds is not None


def test_forget_removes_credentials_and_cursors_but_keeps_rows(
    forget_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(["mail", "forget", "--yes"], capsys)
    assert code == 0, err
    assert forget_env["secrets"].creds is None
    assert store.meta_items("mail_imap.mail.") == {}
    assert int(store.status()["sources"]["mail"]["messages"]) == 3
    assert "Removed 2 cursor record(s)." in out


def test_forget_rows_also_deletes_the_account_rows(
    forget_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(["mail", "forget", "--rows", "--yes"], capsys)
    assert code == 0, err
    assert "Deleted 3 imported mail message(s)" in out
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]
    assert forget_env["secrets"].creds is None


def test_forget_rows_stops_when_the_store_refuses(
    forget_env: dict[str, Any], store: ImportStore, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(_home: Path) -> ImportStore:
        raise ImportRefused("not_armed")

    monkeypatch.setattr(mail_sync_cli, "_open_store", refuse)
    code, _out, err = run(["mail", "forget", "--rows", "--yes"], capsys)
    assert code == 1 and "not_armed" in err
    assert forget_env["secrets"].creds is not None  # nothing touched
    assert int(store.status()["sources"]["mail"]["messages"]) == 3


def test_parsers_wire_the_new_commands() -> None:
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    for argv in (["mail", "setup"], ["mail", "fetch", "--json"], ["mail", "forget", "--yes"]):
        assert parser.parse_args(argv).func is cli._handle_mail
    ns = parser.parse_args(["mail", "fetch"])
    assert (ns.max, ns.mailbox, ns.since, ns.dry_run) == (2000, None, None, False)


def test_mail_import_shares_the_writer_lock(store: ImportStore, home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import sys

    if sys.platform == "win32":
        pytest.skip("POSIX flock")
    from mordred_hermes.imports.mail.imap_sync import fetch_lock

    mbox = str(Path(__file__).parent / "fixtures" / "mail" / "takeout_small.mbox")
    argv = ["mail", "import", "--mbox", mbox, "--own-address", "owner@example.com", "--account", "work"]
    with fetch_lock(home):
        code, _out, err = run(argv, capsys)
    assert code == 1 and "sync_in_progress" in err
    assert rows(store, "SELECT count(*) FROM import_runs") == [(0,)]


# --- setup and forget under the writer lock ----------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_setup_takes_the_writer_lock(
    setup_env: dict[str, Any], home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mordred_hermes.imports.mail.imap_sync import fetch_lock

    server = gmail_server()
    use_server(monkeypatch, server)
    setup_env["answers"].extend(["owner@example.com", ""])
    with fetch_lock(home):
        code, _out, err = run(["mail", "setup", "--imap-host", "imap.example.com"], capsys)
    assert code == 1 and "sync_in_progress" in err
    assert setup_env["store"].flags() is None and server.commands == []  # neither probed nor sealed


def test_setup_refuses_every_port_but_993(setup_env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    for port in ("143", "465", "994"):
        try:
            code = cli.main(["mail", "setup", "--imap-port", port])
        except SystemExit as exc:
            code = int(exc.code or 0)
        capsys.readouterr()
        assert code == 2 and setup_env["store"].flags() is None and setup_env["prompts"] == []


def test_forget_rows_is_retryable_after_the_credentials_are_gone(
    forget_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    forget_env["secrets"].creds = None  # an earlier plain forget removed the credentials and the label with them
    code, out, err = run(["mail", "forget", "--rows", "--yes"], capsys)
    assert code == 0 and "No mail credentials" in out
    assert int(store.status()["sources"]["mail"]["messages"]) == 3  # without a label nothing is guessed
    code, out, err = run(["mail", "forget", "--rows", "--yes", "--account", "mail"], capsys)
    assert code == 0, err
    assert "Deleted 3 imported mail message(s)" in out and "Removed 2 cursor record(s)." in out
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)]
    assert store.meta_items("mail_imap.mail.") == {}


def test_forget_deletes_rows_first_and_credentials_last(
    forget_env: dict[str, Any], store: ImportStore, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    order: list[str] = []
    real_delete = store.delete_source

    def delete_source(*args: Any) -> int:
        order.append("rows")
        assert forget_env["secrets"].creds is not None  # the credentials still exist while rows go
        return real_delete(*args)

    monkeypatch.setattr(store, "delete_source", delete_source)
    real_forget = forget_env["secrets"].forget

    def forget() -> None:
        order.append("credentials")
        real_forget()

    monkeypatch.setattr(forget_env["secrets"], "forget", forget)
    assert run(["mail", "forget", "--rows", "--yes"], capsys)[0] == 0
    assert order == ["rows", "credentials"]


def test_forget_with_another_label_than_the_sealed_one_touches_nothing(
    forget_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _out, err = run(["mail", "forget", "--rows", "--yes", "--account", "work"], capsys)
    assert code == 1 and "account_mismatch" in err
    assert forget_env["secrets"].creds is not None
    assert int(store.status()["sources"]["mail"]["messages"]) == 3


def test_a_setup_that_ran_before_the_lock_is_never_undone_by_forget(
    forget_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets = forget_env["secrets"]
    seen: list[int] = []
    real_flags = secrets.flags

    def flags() -> dict[str, Any] | None:
        value = real_flags()
        seen.append(1)
        if value is not None:  # the second read (under the lock) sees a NEW setup under the same label
            value = {**value, "setup_id": "first" if len(seen) == 1 else "second"}
        return value

    secrets.flags = flags  # type: ignore[method-assign]
    code, _out, err = run(["mail", "forget", "--rows", "--yes"], capsys)
    assert code == 1 and "credentials_changed" in err
    assert secrets.creds is not None  # the fresh credentials stay
    assert int(store.status()["sources"]["mail"]["messages"]) == 3 and store.meta_items("mail_imap.mail.")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_forget_waits_for_no_one_while_a_fetch_runs(
    forget_env: dict[str, Any], store: ImportStore, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from mordred_hermes.imports.mail.imap_sync import fetch_lock

    with fetch_lock(home):
        code, _out, err = run(["mail", "forget", "--rows", "--yes"], capsys)
    assert code == 1 and "sync_in_progress" in err
    assert forget_env["secrets"].creds is not None
    assert int(store.status()["sources"]["mail"]["messages"]) == 3


# --- forget whatever the flags say -------------------------------------------------------------------


@pytest.fixture
def sealed_forget_env(
    tmp_path: Path, home: Path, store: ImportStore, fetch_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Rows and cursors of account ``mail`` and REAL sealed credentials (fake Enclave) for that label."""
    from mordred_hermes.imports.mail.imap_sync import FetchOptions, run_fetch
    from mordred_hermes.imports.mail.secrets import KEY_ID
    from tests._platform_test_helpers import require_posix_tee

    require_posix_tee()
    assert run_fetch(FetchOptions(), fetch_env["env"]).inserted == 3
    enclave = FakeEnclave()
    secret_store = sealed_store(tmp_path / "sealed", enclave)
    secret_store.ensure_key()
    secret_store.store(gmail_creds())
    monkeypatch.setattr(mail_sync_cli, "_secret_store", lambda: secret_store)
    assert KEY_ID in enclave.keys and store.meta_items("mail_imap.mail.")
    return {"store": secret_store, "enclave": enclave}


def _gone(env: dict[str, Any]) -> bool:
    from mordred_hermes.imports.mail.secrets import KEY_ID

    secret_store = env["store"]
    return not secret_store.sealed_path.exists() and not secret_store.residue() and KEY_ID not in env["enclave"].keys


def test_forget_deletes_credentials_whose_flags_are_corrupt(
    sealed_forget_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    sealed_forget_env["store"].meta_path.write_text("{corrupt")
    code, out, err = run(["mail", "forget", "--yes"], capsys)
    assert code == 1 and "Mail credentials removed." in out and "account_unknown" in err
    assert _gone(sealed_forget_env)  # the sealed file, the flags and the Enclave key, whatever the flags said
    assert store.meta_items("mail_imap.mail.")  # the label could not be read: cursors are kept, and said so
    code, out, err = run(["mail", "forget", "--yes", "--account", "mail"], capsys)
    assert code == 0, err
    assert "Removed 2 cursor record(s)." in out and store.meta_items("mail_imap.mail.") == {}


def test_forget_with_missing_flags_and_a_label_deletes_everything(
    sealed_forget_env: dict[str, Any], store: ImportStore, capsys: pytest.CaptureFixture[str]
) -> None:
    sealed_forget_env["store"].meta_path.unlink()  # a setup interrupted between its two files
    assert sealed_forget_env["store"].flags() is None
    code, out, err = run(["mail", "forget", "--rows", "--yes", "--account", "mail"], capsys)
    assert code == 0, err
    assert "Mail credentials removed." in out and "Deleted 3 imported mail message(s)" in out
    assert _gone(sealed_forget_env)
    assert rows(store, "SELECT count(*) FROM import_messages") == [(0,)] and store.meta_items("mail_imap.mail.") == {}
    assert rows(store, "SELECT count(*) FROM import_mail_refs") == [(0,)]


def test_forget_is_retried_after_a_partial_deletion(
    sealed_forget_env: dict[str, Any],
    store: ImportStore,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_store = sealed_forget_env["store"]
    real_unlink = Path.unlink

    def flaky(path: Path, missing_ok: bool = False) -> None:
        if path == secret_store.meta_path:
            raise PermissionError("flags file busy")
        real_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", flaky)
    code, out, err = run(["mail", "forget", "--yes"], capsys)
    assert code == 1 and "removed" not in out  # the sealed file went, the flags did not: no success reported
    assert not secret_store.sealed_path.exists() and secret_store.residue() and secret_store.flags() is None
    monkeypatch.setattr(Path, "unlink", real_unlink)
    code, out, err = run(["mail", "forget", "--yes", "--account", "mail"], capsys)  # the retry finishes the job
    assert code == 0, err
    assert "Mail credentials removed." in out and _gone(sealed_forget_env)
    assert store.meta_items("mail_imap.mail.") == {}


def test_forget_never_reports_success_while_a_sealed_file_remains(
    sealed_forget_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_store = sealed_forget_env["store"]
    monkeypatch.setattr(secret_store, "forget", lambda: True)  # claims success, deletes nothing
    code, out, err = run(["mail", "forget", "--yes"], capsys)
    assert code == 1 and "credentials_left" in err and "removed" not in out
    assert secret_store.sealed_path.exists()


def test_forget_reports_an_enclave_key_it_could_not_delete(
    sealed_forget_env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    from mordred_hermes.imports.mail.secrets import KEY_ID

    enclave = sealed_forget_env["enclave"]
    real_delete = enclave.delete_enclave_key

    def broken(_key_id: str) -> None:
        raise OSError("keychain unavailable")

    enclave.delete_enclave_key = broken
    code, _out, err = run(["mail", "forget", "--yes"], capsys)
    assert code == 1 and "key_left" in err and KEY_ID in enclave.keys
    assert not sealed_forget_env["store"].sealed_path.exists()
    code, out, err = run(["mail", "forget", "--yes"], capsys)  # no file is left, the key still cannot go
    assert code == 1 and "key_left" in err and KEY_ID in enclave.keys
    assert "No mail credentials were set up." in out
    enclave.delete_enclave_key = real_delete
    code, _out, err = run(["mail", "forget", "--yes"], capsys)  # nothing left on disk: the retry deletes the key
    assert code == 0, err
    assert KEY_ID not in enclave.keys
