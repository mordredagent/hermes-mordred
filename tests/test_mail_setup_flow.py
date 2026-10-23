"""The step-wise IMAP mail setup shared by ``mail setup`` and the Desktop page (``imports/mail/setup_flow.py``).

The flow runs against the scripted IMAP server of ``tests/_fake_imap.py`` (the real
imaplib client over a socket pair), a real :class:`MailSecretStore` on a fake
Enclave and the real per-home writer lock. Secrets, addresses and folder names
are canaries: they must never reach a ``repr``, an exception or a log line.
"""

from __future__ import annotations

import contextlib
import gc
import logging
import sys
import traceback
import weakref
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports.mail import setup_flow
from mordred_hermes.imports.mail._imap_codec import encode_mutf7
from mordred_hermes.imports.mail.imap import ImapError, ImapStopped
from mordred_hermes.imports.mail.imap_sync import fetch_lock
from mordred_hermes.imports.mail.secrets import KEY_ID, MailSecretsError, MailSecretStore
from mordred_hermes.imports.mail.setup_flow import SETUP_ERROR_CODES, MailSetupError, MailSetupFlows
from tests._fake_imap import FakeImapServer, FakeMailbox
from tests._mail_sync_helpers import ADDRESS, PASSWORD, Clock, generic_creds, gmail_server
from tests.test_mail_secrets import FakeEnclave, sealed_store

FOLDER_CANARY = "FOLDERCANARY"
ALERT_CANARY = "ALERTCANARY-owner@example.com-https://support.example.com/answer/185833"
GMAIL_APP_PASSWORD = "abcd efgh ijkl mnop"  # as Google shows it: four groups of four letters


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def enclave() -> FakeEnclave:
    from tests._platform_test_helpers import require_posix_tee

    require_posix_tee()
    return FakeEnclave()


@pytest.fixture
def secrets(tmp_path: Path, enclave: FakeEnclave) -> MailSecretStore:
    return sealed_store(tmp_path / "sealed", enclave)


class Connector:
    """``connect(host, port)`` for the flow: a session on the scripted server, every call recorded."""

    def __init__(self, server: FakeImapServer | None = None, error: ImapError | None = None) -> None:
        self.server = server
        self.error = error
        self.calls: list[tuple[str, int]] = []

    def __call__(self, host: str, port: int) -> Any:
        self.calls.append((host, port))
        if self.error is not None:
            raise self.error
        assert self.server is not None
        return self.server.session()


def make_flows(
    secrets: Any, home: Path, connect: Any, *, clock: Clock | None = None, lock: Any = fetch_lock
) -> MailSetupFlows:
    return MailSetupFlows(secrets, connect=connect, lock=lock, home=lambda: home, clock=clock or Clock())


def start(flows: MailSetupFlows, **overrides: Any) -> setup_flow.MailSetupFlow:
    values: dict[str, Any] = {
        "address": ADDRESS,
        "imap_host": "imap.example.com",
        "account": "mail",
        "extra_addresses": (),
        "app_password": PASSWORD,
        "presence": True,
    }
    values.update(overrides)
    return flows.start(**values)


def credential_files(secrets: MailSecretStore) -> list[str]:
    folder = secrets.sealed_path.parent
    return sorted(path.name for path in folder.glob("*credentials.*")) if folder.exists() else []


def no_folder_server(**kwargs: Any) -> FakeImapServer:
    """A generic server that marks no sent folder (folder names are canaries)."""
    boxes = {
        "INBOX": FakeMailbox(1),
        f"Gesendet-{FOLDER_CANARY}": FakeMailbox(2),
        f"Archiv-{FOLDER_CANARY}": FakeMailbox(3),
    }
    return FakeImapServer(boxes, **kwargs)


def pending(flows: MailSetupFlows) -> int:
    return int(repr(flows).removeprefix("MailSetupFlows(pending=").removesuffix(")"))


# --- the Gmail path -----------------------------------------------------------------------------------


def test_gmail_seals_all_mail_at_once(secrets: MailSecretStore, enclave: FakeEnclave, home: Path) -> None:
    server = gmail_server()
    connect = Connector(server)
    flows = make_flows(secrets, home, connect)
    flow = start(flows, account="work", extra_addresses=["Old.Me@example.org", " "], presence=True)
    assert (flow.step, flow.gmail, flow.question, flow.folders) == ("done", True, None, ())
    assert (flow.account, flow.roles, flow.presence) == ("work", ("all",), True)
    assert connect.calls == [("imap.example.com", 993)]
    creds = secrets.load()
    assert creds is not None
    assert (creds.account, creds.gmail, creds.mailboxes) == ("work", True, {"all": "[Gmail]/All Mail"})
    assert creds.own_addresses == ("old.me@example.org", ADDRESS)
    assert (creds.app_password, creds.imap_host, creds.imap_port) == (PASSWORD, "imap.example.com", 993)
    assert (secrets.flags() or {})["touch_id"] is True and enclave.unattended == {KEY_ID: False}
    assert server.violations == [] and server.verbs == ["CAPABILITY", "LOGIN", "CAPABILITY", "LIST", "LOGOUT"]
    assert pending(flows) == 0  # a finished flow is never kept


def test_gmail_falls_back_to_the_all_mail_name(secrets: MailSecretStore, home: Path) -> None:
    boxes = {"INBOX": FakeMailbox(1), "[Google Mail]/All Mail": FakeMailbox(2)}
    flow = start(make_flows(secrets, home, Connector(FakeImapServer(boxes, gmail=True))))
    assert flow.step == "done"
    assert secrets.load().mailboxes == {"all": "[Google Mail]/All Mail"}  # type: ignore[union-attr]


def test_gmail_without_a_known_all_mail_asks_which_folder_it_is(secrets: MailSecretStore, home: Path) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(1), f"Alle-{FOLDER_CANARY}": FakeMailbox(2)}, gmail=True)
    flows = make_flows(secrets, home, Connector(server))
    flow = start(flows)
    assert (flow.step, flow.question, flow.gmail, flow.roles) == ("folders", "all_mail", True, ())
    assert [folder.name for folder in flow.folders] == ["INBOX", f"Alle-{FOLDER_CANARY}"]
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)  # All Mail is not optional
    assert raised.value.code == "invalid_selection" and credential_files(secrets) == []
    done = flows.finish(flow.flow_id, selection=f"Alle-{FOLDER_CANARY}")
    assert (done.step, done.question, done.roles, done.folders) == ("done", None, ("all",), ())
    creds = secrets.load()
    assert creds is not None and (creds.gmail, creds.mailboxes) == (True, {"all": f"Alle-{FOLDER_CANARY}"})


def test_gmail_without_any_selectable_folder_is_a_protocol_failure(secrets: MailSecretStore, home: Path) -> None:
    server = FakeImapServer({"Public": FakeMailbox(1, attributes=("\\Noselect",))}, gmail=True)
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(server)))
    assert raised.value.code == "imap_protocol" and credential_files(secrets) == []
    assert "LOGOUT" in server.verbs


def test_gmail_app_password_spaces_are_stripped_and_the_host_defaults(secrets: MailSecretStore, home: Path) -> None:
    server = gmail_server(user="owner@gmail.com", password="abcdefghijklmnop")
    connect = Connector(server)
    flow = start(make_flows(secrets, home, connect), address="Owner@Gmail.com", imap_host=None,
                 app_password=GMAIL_APP_PASSWORD)  # fmt: skip
    assert flow.step == "done" and connect.calls == [("imap.gmail.com", 993)]
    creds = secrets.load()
    assert creds is not None
    assert (creds.address, creds.app_password) == ("owner@gmail.com", "abcdefghijklmnop")
    assert creds.imap_host == "imap.gmail.com"


@pytest.mark.parametrize("password", ["my-account-password", "abcd efgh ijkl mno", "abcd efgh ijkl mnop q"])
def test_a_gmail_password_of_another_length_never_connects(
    password: str, secrets: MailSecretStore, enclave: FakeEnclave, home: Path
) -> None:
    connect = Connector(gmail_server())
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, connect), imap_host="imap.gmail.com", app_password=password)
    assert (raised.value.code, raised.value.hint) == ("imap_auth_failed", "gmail_app_password_length")
    assert connect.calls == [] and enclave.keys == {} and credential_files(secrets) == []
    assert not (home / "mordred").exists()  # not even the lock was taken


# --- the generic path ---------------------------------------------------------------------------------


def test_generic_server_with_a_special_use_sent_folder_seals_at_once(secrets: MailSecretStore, home: Path) -> None:
    boxes = {"INBOX": FakeMailbox(1), "Sent Items": FakeMailbox(2, attributes=("\\Sent",))}
    flow = start(make_flows(secrets, home, Connector(FakeImapServer(boxes))), presence=False)
    assert (flow.step, flow.gmail, flow.roles) == ("done", False, ("inbox", "sent"))
    creds = secrets.load()
    assert creds is not None and creds.mailboxes == {"inbox": "INBOX", "sent": "Sent Items"}
    assert (secrets.flags() or {})["touch_id"] is False


def test_generic_server_without_a_sent_folder_asks_and_finish_seals(secrets: MailSecretStore, home: Path) -> None:
    server = no_folder_server()
    flows = make_flows(secrets, home, Connector(server))
    flow = start(flows)
    assert (flow.step, flow.question, flow.gmail, flow.roles) == ("folders", "sent", False, ())
    assert [(folder.name, folder.display) for folder in flow.folders] == [
        ("INBOX", "INBOX"),
        (f"Gesendet-{FOLDER_CANARY}", f"Gesendet-{FOLDER_CANARY}"),
        (f"Archiv-{FOLDER_CANARY}", f"Archiv-{FOLDER_CANARY}"),
    ]
    assert credential_files(secrets) == [] and pending(flows) == 1  # nothing is written before the seal
    assert "LOGOUT" in server.verbs  # the connection is closed while the owner chooses
    assert flows.get(flow.flow_id) is flow
    done = flows.finish(flow.flow_id, selection=f"Gesendet-{FOLDER_CANARY}")
    assert done is flow and (done.step, done.question, done.roles) == ("done", None, ("inbox", "sent"))
    creds = secrets.load()
    assert creds is not None and creds.mailboxes == {"inbox": "INBOX", "sent": f"Gesendet-{FOLDER_CANARY}"}
    assert pending(flows) == 0
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "mail_setup_flow_expired"


@pytest.mark.parametrize("selection", [None, "INBOX"])
def test_no_sent_folder_seals_the_inbox_only(selection: str | None, secrets: MailSecretStore, home: Path) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    assert flows.finish(flow.flow_id, selection=selection).roles == ("inbox",)
    assert secrets.load().mailboxes == {"inbox": "INBOX"}  # type: ignore[union-attr]


@pytest.mark.parametrize("selection", ["Trash", "", 7, ["INBOX"]])
def test_a_selection_the_flow_never_offered_changes_nothing(
    selection: Any, secrets: MailSecretStore, home: Path
) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=selection)
    assert raised.value.code == "invalid_selection" and credential_files(secrets) == []
    assert flows.finish(flow.flow_id, selection=None).step == "done"  # the flow is still there to retry


def test_a_server_without_selectable_folders_seals_the_inbox(secrets: MailSecretStore, home: Path) -> None:
    server = FakeImapServer({"Public": FakeMailbox(1, attributes=("\\Noselect",))})
    flow = start(make_flows(secrets, home, Connector(server)))
    assert (flow.step, flow.roles) == ("done", ("inbox",))


def test_folder_display_names_are_terminal_safe_and_bounded(secrets: MailSecretStore, home: Path) -> None:
    long_name = "L" * 300
    boxes = {
        "INBOX": FakeMailbox(1),
        encode_mutf7("\x07bell"): FakeMailbox(2),
        encode_mutf7("日本語"): FakeMailbox(3),
        long_name: FakeMailbox(4),
        "Hidden": FakeMailbox(5, attributes=("\\Noselect",)),
    }
    flow = start(make_flows(secrets, home, Connector(FakeImapServer(boxes))))
    displays = {folder.name: folder.display for folder in flow.folders}
    assert displays == {
        "INBOX": "INBOX",
        "&AAc-bell": "\\x07bell",
        "&ZeVnLIqe-": "日本語",
        long_name: "L" * 200,
    }


# --- the registry: bound, TTL, cancel, references ------------------------------------------------------


def test_one_flow_waits_at_a_time(secrets: MailSecretStore, home: Path) -> None:
    connect = Connector(no_folder_server())
    flows = make_flows(secrets, home, connect)
    first = start(flows)
    with pytest.raises(MailSetupError) as raised:
        start(flows)
    assert raised.value.code == "mail_setup_busy" and len(connect.calls) == 1  # refused before the server
    flows.cancel(first.flow_id)
    second = start(flows)
    assert pending(flows) == 1 and flows.finish(second.flow_id, selection=None).step == "done"


def test_a_flow_expires_after_ten_minutes(secrets: MailSecretStore, home: Path) -> None:
    clock = Clock()
    flows = make_flows(secrets, home, Connector(no_folder_server()), clock=clock)
    flow = start(flows)
    clock.now = setup_flow.FLOW_TTL_SECONDS + 0.5
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "mail_setup_flow_expired"
    assert credential_files(secrets) == [] and pending(flows) == 0


@pytest.mark.parametrize("call", ["get", "cancel", "start"])
def test_an_expired_flow_is_gone_after_the_next_call(call: str, secrets: MailSecretStore, home: Path) -> None:
    clock = Clock()
    flows = make_flows(secrets, home, Connector(no_folder_server()), clock=clock)
    flow = start(flows)
    clock.now = setup_flow.FLOW_TTL_SECONDS + 1
    if call == "get":
        with pytest.raises(MailSetupError):
            flows.get("another id")
    elif call == "cancel":
        flows.cancel("another id")
    else:
        start(flows)
    assert flow.flow_id not in flows._entries
    assert pending(flows) == (1 if call == "start" else 0)


def test_a_flow_within_its_ttl_still_finishes(secrets: MailSecretStore, home: Path) -> None:
    clock = Clock()
    flows = make_flows(secrets, home, Connector(no_folder_server()), clock=clock)
    flow = start(flows)
    clock.now = setup_flow.FLOW_TTL_SECONDS
    assert flows.finish(flow.flow_id, selection=None).step == "done"


def test_a_flow_that_expires_while_finish_waits_for_the_lock_seals_nothing(
    secrets: MailSecretStore, home: Path
) -> None:
    clock = Clock()

    @contextlib.contextmanager
    def slow_lock(path: Path) -> Iterator[None]:
        clock.now += setup_flow.FLOW_TTL_SECONDS + 1  # the lock was held by a long fetch
        with fetch_lock(path):
            yield

    flows = make_flows(secrets, home, Connector(no_folder_server()), clock=clock, lock=fetch_lock)
    flow = start(flows)
    flows._lock = slow_lock
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "mail_setup_flow_expired" and credential_files(secrets) == []


def test_cancel_and_cancel_all_drop_the_flows_and_seal_nothing(secrets: MailSecretStore, home: Path) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    flows.cancel(flow.flow_id)
    flows.cancel(flow.flow_id)  # idempotent
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "mail_setup_flow_expired" and credential_files(secrets) == []
    again = start(flows)
    flows.cancel_all()
    assert pending(flows) == 0
    with pytest.raises(MailSetupError):
        flows.get(again.flow_id)


def test_reap_expires_flows_while_nothing_else_happens(secrets: MailSecretStore, home: Path) -> None:
    clock = Clock()
    flows = make_flows(secrets, home, Connector(no_folder_server()), clock=clock)
    start(flows)
    clock.now = setup_flow.FLOW_TTL_SECONDS
    flows.reap()
    assert pending(flows) == 1
    clock.now += 0.5
    flows.reap()  # the Desktop backend's periodic task: no request needed
    assert pending(flows) == 0 and credential_files(secrets) == []


@pytest.mark.parametrize("end", ["finish", "cancel", "cancel_all", "expiry"])
def test_every_reference_to_the_password_is_dropped(end: str, secrets: MailSecretStore, home: Path) -> None:
    clock = Clock()
    flows = make_flows(secrets, home, Connector(no_folder_server()), clock=clock)
    flow = start(flows)
    provisional = weakref.ref(flows._entries[flow.flow_id].provisional)
    if end == "finish":
        flows.finish(flow.flow_id, selection=None)
    elif end == "cancel":
        flows.cancel(flow.flow_id)
    elif end == "cancel_all":
        flows.cancel_all()
    else:
        clock.now = setup_flow.FLOW_TTL_SECONDS + 1
        flows.cancel("another id")
    gc.collect()
    assert provisional() is None  # the address and the password are unreachable
    assert [value for value in vars(flow).values() if value in (PASSWORD, ADDRESS)] == []


def test_a_key_deleted_meanwhile_is_recreated_with_the_recorded_policy(
    secrets: MailSecretStore, enclave: FakeEnclave, home: Path
) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows, presence=False)
    assert flow.presence is False
    enclave.keys.clear()  # the Enclave lost the key (no forget: the generation is unchanged)
    assert flows.finish(flow.flow_id, selection=None).step == "done"
    assert enclave.unattended == {KEY_ID: True} and (secrets.flags() or {})["touch_id"] is False


def test_a_forget_between_start_and_finish_makes_the_flow_stale(secrets: MailSecretStore, home: Path) -> None:
    from mordred_hermes.imports.mail.forget import forget

    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    forget(secrets, home, open_store=lambda _home: None)  # `mail forget --yes` in a terminal, nothing sealed yet
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "mail_setup_stale" and credential_files(secrets) == [] and pending(flows) == 0


def test_a_seal_elsewhere_and_its_forget_make_the_flow_stale(secrets: MailSecretStore, home: Path) -> None:
    from mordred_hermes.imports.mail.forget import forget

    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    other = make_flows(secrets, home, Connector(gmail_server()))  # the CLI in another process
    start(other)
    forget(secrets, home, open_store=lambda _home: None)
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "mail_setup_stale" and credential_files(secrets) == []


def test_every_seal_rewrites_the_setup_generation(secrets: MailSecretStore, home: Path) -> None:
    from mordred_hermes.imports.mail.secrets import GENERATION_ABSENT, setup_generation

    assert setup_generation(home) == GENERATION_ABSENT
    start(make_flows(secrets, home, Connector(gmail_server())))
    sealed = setup_generation(home)
    assert sealed != GENERATION_ABSENT and ((home / "mordred" / "mail" / "generation").stat().st_mode & 0o777) == 0o600


def test_finish_refuses_a_key_whose_policy_changed(secrets: MailSecretStore, home: Path) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows, presence=True)
    secrets.ensure_key(require_presence=False, replace=True)  # another setup replaced the key, then failed
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "touch_id_policy_mismatch" and credential_files(secrets) == []
    assert pending(flows) == 0


def test_finish_refuses_a_key_of_unknown_policy(secrets: MailSecretStore, home: Path) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    secrets.key_record_path.unlink()  # a key this store did not create (or whose record was lost)
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "touch_id_policy_mismatch"


# --- hints and failures -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "hint"),
    [
        (lambda: gmail_server(password="another"), "authentication_failed"),
        (lambda: gmail_server(password="another", login_failure=f"NO [ALERT] {ALERT_CANARY}"), "server_alert"),
        (lambda: gmail_server(password="another", login_failure="NO Invalid credentials"), None),
        (lambda: gmail_server(capabilities=("LOGINDISABLED",)), "login_disabled"),
    ],
)
def test_login_failures_pass_the_hint_and_seal_nothing(
    server: Any, hint: str | None, secrets: MailSecretStore, home: Path
) -> None:
    fake = server()
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(fake)))
    assert (raised.value.code, raised.value.hint) == ("imap_auth_failed", hint)
    assert credential_files(secrets) == [] and "LOGOUT" in fake.verbs


def test_the_server_alert_text_never_reaches_the_error_or_the_log(
    secrets: MailSecretStore, home: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    server = gmail_server(password="another", login_failure=f"NO [ALERT] {ALERT_CANARY} (Failure)")
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(server)))
    error = raised.value
    rendered = [str(error), repr(error), repr(error.args), repr(vars(error)), caplog.text]
    rendered.append("".join(traceback.format_exception(error)))
    assert [text for text in rendered if "ALERTCANARY" in text or PASSWORD in text or ADDRESS in text] == []
    assert (error.code, error.hint, error.args) == ("imap_auth_failed", "server_alert", ("imap_auth_failed",))


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ImapError("imap_unreachable"), "imap_unreachable"),
        (ImapError("routing_unavailable"), "routing_unavailable"),
        (ImapError("egress_unsupported"), "egress_unsupported"),
        (ImapError("imap_protocol"), "imap_protocol"),
        (ImapError("imap_command_refused"), "imap_command_refused"),
        (ImapError("something_new"), "imap_protocol"),
        (ImapStopped("time_budget"), "imap_unreachable"),
        (ImapStopped("cancelled"), "imap_unreachable"),
    ],
)
def test_connection_failures_are_codes(error: ImapError, code: str, secrets: MailSecretStore, home: Path) -> None:
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(error=error)))
    assert (raised.value.code, raised.value.hint) == (code, None) and credential_files(secrets) == []


class FakeSession:
    """An ``ImapSession`` stand-in for failures the scripted server does not produce."""

    def __init__(self, *, list_error: ImapError | None = None) -> None:
        self.gmail = False
        self.list_error = list_error
        self.logged_out = False

    def login(self, _user: str, _password: str) -> None:
        return None

    def list_mailboxes(self) -> list[Any]:
        if self.list_error is not None:
            raise self.list_error
        return []

    def logout(self) -> None:
        self.logged_out = True


def test_a_failed_list_is_a_code_and_the_session_is_closed(secrets: MailSecretStore, home: Path) -> None:
    session = FakeSession(list_error=ImapStopped("time_budget"))
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, lambda _host, _port: session))
    assert raised.value.code == "imap_unreachable" and session.logged_out and credential_files(secrets) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_a_held_writer_lock_is_sync_in_progress(secrets: MailSecretStore, enclave: FakeEnclave, home: Path) -> None:
    connect = Connector(gmail_server())
    with fetch_lock(home), pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, connect))
    assert raised.value.code == "sync_in_progress"
    assert connect.calls == [] and enclave.keys == {} and credential_files(secrets) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_finish_retakes_the_writer_lock(secrets: MailSecretStore, home: Path) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    with fetch_lock(home), pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "sync_in_progress" and credential_files(secrets) == []
    assert flows.finish(flow.flow_id, selection=None).step == "done"  # retried once the lock is free


def test_an_unsafe_mail_directory_is_store_path_unsafe(secrets: MailSecretStore, home: Path, tmp_path: Path) -> None:
    (home / "mordred").mkdir()
    (home / "mordred" / "mail").symlink_to(tmp_path)
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(gmail_server())))
    assert raised.value.code == "store_path_unsafe"


# --- admission under the lock, the Enclave key and sealing --------------------------------------------


def test_sealed_credentials_are_never_replaced(secrets: MailSecretStore, enclave: FakeEnclave, home: Path) -> None:
    secrets.ensure_key()
    secrets.store(generic_creds(account="first"))
    key = enclave.keys[KEY_ID]
    connect = Connector(gmail_server())
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, connect))
    assert raised.value.code == "mail_already_configured" and connect.calls == []
    assert secrets.load().account == "first" and enclave.keys[KEY_ID] is key  # type: ignore[union-attr]


def test_a_residue_without_flags_is_already_configured(secrets: MailSecretStore, home: Path) -> None:
    secrets.ensure_key()
    secrets.store(generic_creds(account="first"))
    secrets.meta_path.unlink()  # credentials_left: the owner removes them with `mail forget`
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(gmail_server())))
    assert raised.value.code == "mail_already_configured" and secrets.sealed_path.exists()


def test_admission_is_decided_under_the_lock(secrets: MailSecretStore, enclave: FakeEnclave, home: Path) -> None:
    @contextlib.contextmanager
    def racing_lock(path: Path) -> Iterator[None]:
        secrets.ensure_key()
        secrets.store(generic_creds(account="other"))  # another setup sealed while this one waited
        with fetch_lock(path):
            yield

    connect = Connector(gmail_server())
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, connect, lock=racing_lock))
    assert raised.value.code == "mail_already_configured" and connect.calls == []
    assert secrets.load().account == "other"  # type: ignore[union-attr]  # its key was never replaced


def test_a_cli_setup_between_start_and_finish_wins(secrets: MailSecretStore, home: Path) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    secrets.store(generic_creds(account="other"))  # `mail setup` in a terminal finished meanwhile
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "mail_already_configured" and pending(flows) == 0
    assert secrets.load().account == "other"  # type: ignore[union-attr]


def test_a_key_left_by_a_failed_setup_gets_the_requested_policy(
    secrets: MailSecretStore, enclave: FakeEnclave, home: Path
) -> None:
    with pytest.raises(MailSetupError):
        start(make_flows(secrets, home, Connector(gmail_server(password="wrong"))), presence=False)
    assert enclave.unattended == {KEY_ID: True} and credential_files(secrets) == []  # an unattended key is left
    start(make_flows(secrets, home, Connector(gmail_server())), presence=True)
    assert (secrets.flags() or {})["touch_id"] is True
    assert enclave.unattended == {KEY_ID: False}  # the key really requires presence now


def test_a_left_key_that_cannot_be_deleted_is_a_policy_mismatch(
    secrets: MailSecretStore, enclave: FakeEnclave, home: Path
) -> None:
    secrets.ensure_key(require_presence=False)

    def broken(_key_id: str) -> None:
        raise OSError("keychain unavailable")

    enclave.delete_enclave_key = broken  # type: ignore[method-assign]
    connect = Connector(gmail_server())
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, connect), presence=True)
    assert raised.value.code == "touch_id_policy_mismatch" and connect.calls == []


class RecordingSecrets:
    """The secret-store calls the flow makes, in order."""

    def __init__(self, events: list[Any], *, key_error: str | None = None, effective: Any = "requested") -> None:
        self.events = events
        self.key_error = key_error
        self.effective = effective
        self.present = False

    def residue(self) -> bool:
        self.events.append("residue")
        return self.present

    def ensure_key(self, *, require_presence: bool = True, replace: bool = False) -> bool | None:
        self.events.append(("ensure_key", require_presence, replace))
        if self.key_error is not None:
            raise MailSecretsError(self.key_error)
        return require_presence if self.effective == "requested" else self.effective

    def store(self, value: Any, *, require_presence: bool = True) -> None:
        self.events.append(("store", require_presence))
        self.present = True

    def forget(self) -> bool:
        self.events.append("forget")
        return True


@pytest.mark.parametrize("presence", [True, False])
def test_admission_then_the_key_then_the_server_then_the_seal(presence: bool, home: Path) -> None:
    events: list[Any] = []
    server = gmail_server()

    def connect(_host: str, _port: int) -> Any:
        events.append("connect")
        return server.session()

    start(make_flows(RecordingSecrets(events), home, connect), presence=presence)
    assert events == ["residue", ("ensure_key", presence, True), "connect", ("store", presence)]


def test_the_flags_record_the_effective_policy(home: Path) -> None:
    events: list[Any] = []
    start(make_flows(RecordingSecrets(events, effective=True), home, Connector(gmail_server())), presence=False)
    assert events[-1] == ("store", True)
    events.clear()
    start(make_flows(RecordingSecrets(events, effective=None), home, Connector(gmail_server())), presence=False)
    assert events[-1] == ("store", False)  # unknown: the requested policy


def test_a_non_boolean_presence_means_touch_id(home: Path) -> None:
    events: list[Any] = []
    start(make_flows(RecordingSecrets(events), home, Connector(gmail_server())), presence="no")
    assert ("ensure_key", True, True) in events


@pytest.mark.parametrize(
    ("code", "expected"),
    [("tee_unavailable", "tee_unavailable"), ("tee_auth_cancelled", "tee_auth_cancelled"),
     ("unsupported_platform", "tee_unavailable"), ("store_path_unsafe", "store_path_unsafe"),
     ("touch_id_policy_mismatch", "touch_id_policy_mismatch")],
)  # fmt: skip
def test_an_enclave_key_failure_stops_before_the_server(code: str, expected: str, home: Path) -> None:
    events: list[Any] = []
    connect = Connector(gmail_server())
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(RecordingSecrets(events, key_error=code), home, connect))
    assert raised.value.code == expected and connect.calls == [] and events == ["residue", ("ensure_key", True, True)]


def test_a_failed_seal_leaves_no_credential_file(
    secrets: MailSecretStore, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_store = secrets.store

    def half_written(value: Any, *, require_presence: bool = True) -> None:
        real_store(value, require_presence=require_presence)
        secrets.meta_path.unlink()  # as if the process lost the flags after the sealed file
        raise OSError("disk full")

    monkeypatch.setattr(secrets, "store", half_written)
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(gmail_server())))
    assert raised.value.code == "store_path_unsafe" and credential_files(secrets) == []


def test_a_seal_the_enclave_refuses_is_tee_unavailable(
    secrets: MailSecretStore, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(_value: Any, *, require_presence: bool = True) -> None:
        raise MailSecretsError("tee_unavailable")

    monkeypatch.setattr(secrets, "store", refused)
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(gmail_server())))
    assert raised.value.code == "tee_unavailable" and credential_files(secrets) == []


def test_a_mailbox_name_the_store_would_refuse_is_a_protocol_failure(secrets: MailSecretStore, home: Path) -> None:
    long_sent = "S" * 1001  # over the sealed payload's limit for a mailbox name
    boxes = {"INBOX": FakeMailbox(1), long_sent: FakeMailbox(2, attributes=("\\Sent",))}
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(FakeImapServer(boxes))))
    assert raised.value.code == "imap_protocol" and credential_files(secrets) == []


# --- validation ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"address": "not an address"}, "invalid_address"),
        ({"address": "a" * 250 + "@example.com"}, "invalid_address"),
        ({"address": None}, "invalid_address"),
        ({"imap_host": "not a host"}, "invalid_host"),
        ({"imap_host": None}, "invalid_host"),  # only Gmail addresses have a default host
        ({"imap_host": 993}, "invalid_host"),
        ({"account": "Work"}, "invalid_account"),
        ({"account": None}, "invalid_account"),
        ({"extra_addresses": ["ok@example.org", "nope"]}, "invalid_address"),
        ({"extra_addresses": "ok@example.org"}, "invalid_address"),
        ({"extra_addresses": [f"a{n}@example.org" for n in range(21)]}, "too_many_addresses"),
        ({"app_password": ""}, "invalid_password"),
        ({"app_password": "x" * 257}, "invalid_password"),
        ({"app_password": "tab\there"}, "invalid_password"),
        ({"app_password": None}, "invalid_password"),
    ],
)
def test_bad_input_is_refused_before_anything_else(
    overrides: dict[str, Any], code: str, secrets: MailSecretStore, enclave: FakeEnclave, home: Path
) -> None:
    connect = Connector(gmail_server())
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, connect), **overrides)
    assert (raised.value.code, raised.value.hint) == (code, None)
    assert connect.calls == [] and enclave.keys == {} and not (home / "mordred").exists()


def test_twenty_extra_addresses_are_accepted(secrets: MailSecretStore, home: Path) -> None:
    extra = [f"a{n}@example.org" for n in range(20)]
    assert start(make_flows(secrets, home, Connector(gmail_server())), extra_addresses=extra).step == "done"
    assert len(secrets.load().own_addresses) == 21  # type: ignore[union-attr]


def test_the_validators_normalise_what_the_cli_types() -> None:
    assert setup_flow.check_address("  Owner@Example.COM ") == "owner@example.com"
    assert setup_flow.default_host("me@googlemail.com") == "imap.gmail.com"
    assert setup_flow.default_host("me@example.com") is None
    assert setup_flow.check_host(" IMAP.Example.com ") == "imap.example.com"
    assert setup_flow.check_password(" a b ", "imap.example.com") == " a b "  # only Gmail's are stripped
    assert setup_flow.check_password(GMAIL_APP_PASSWORD, "imap.gmail.com") == "abcdefghijklmnop"
    assert setup_flow.check_account("work_2") == "work_2"
    assert setup_flow.check_extra_addresses([" A@example.org ", ""]) == ["a@example.org"]
    assert setup_flow.display_name("ok") == "ok" and setup_flow.display_name("\x1b[2J") == "\\x1b[2J"
    assert len(setup_flow.display_name("\x07" * 300)) == 200


# --- what may be printed ------------------------------------------------------------------------------


def test_repr_never_shows_a_secret_an_address_or_a_folder_name(secrets: MailSecretStore, home: Path) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows, extra_addresses=["second@example.org"])
    entry = flows._entries[flow.flow_id]
    shown = " ".join(
        [repr(flow), str(flow), repr(flows), str(flows), repr(flow.folders), repr(flow.folders[1]),
         repr(entry), repr(entry.provisional), repr(entry.provisional.request)]
    )  # fmt: skip
    for secret in (PASSWORD, ADDRESS, "second@example.org", "imap.example.com", flow.flow_id):
        assert secret not in shown
    assert [secret for secret in (PASSWORD, ADDRESS, "imap.example.com") if secret in repr(vars(flow))] == []
    assert FOLDER_CANARY not in shown  # names are reachable through flow.folders only, never printed
    assert "step='folders'" in repr(flow) and "folders=3" in repr(flow)


def test_mail_setup_error_is_a_closed_code_with_a_closed_hint() -> None:
    expected = {
        "invalid_address", "invalid_host", "invalid_account", "invalid_password", "too_many_addresses",
        "mail_already_configured", "mail_setup_flow_expired", "sync_in_progress", "store_path_unsafe",
        "tee_unavailable", "tee_auth_cancelled", "imap_unreachable", "imap_auth_failed", "imap_protocol",
        "imap_command_refused", "routing_unavailable", "egress_unsupported", "touch_id_policy_mismatch",
        "mail_setup_busy", "mail_setup_stale", "invalid_selection",
    }  # fmt: skip
    assert expected == SETUP_ERROR_CODES
    error = MailSetupError("imap_auth_failed", hint="server_alert")
    assert (str(error), error.args, error.code, error.hint) == (
        "imap_auth_failed",
        ("imap_auth_failed",),
        "imap_auth_failed",
        "server_alert",
    )
    assert MailSetupError("imap_auth_failed", hint="free text").hint is None
    with pytest.raises(ValueError):
        MailSetupError("anything else")


# --- defaults ------------------------------------------------------------------------------------------


def test_the_defaults_are_the_real_connect_lock_and_home(
    secrets: MailSecretStore, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.imports.mail import imap

    seen: list[tuple[str, int]] = []

    def refuse(host: str, port: int) -> Any:
        seen.append((host, port))
        raise ImapError("imap_unreachable")

    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(imap, "connect", refuse)
    with pytest.raises(MailSetupError) as raised:
        start(MailSetupFlows(secrets))
    assert raised.value.code == "imap_unreachable" and seen == [("imap.example.com", 993)]
    assert (home / "mordred" / "mail" / ".lock").is_file()


def test_a_finish_whose_seal_failed_can_be_retried(
    secrets: MailSecretStore, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flows = make_flows(secrets, home, Connector(no_folder_server()))
    flow = start(flows)
    real_store = secrets.store
    failures = [MailSecretsError("tee_unavailable")]

    def flaky(value: Any, *, require_presence: bool = True) -> None:
        if failures:
            raise failures.pop()
        real_store(value, require_presence=require_presence)

    monkeypatch.setattr(secrets, "store", flaky)
    with pytest.raises(MailSetupError) as raised:
        flows.finish(flow.flow_id, selection=None)
    assert raised.value.code == "tee_unavailable" and credential_files(secrets) == []
    assert flows.finish(flow.flow_id, selection=None).step == "done"  # not stale: the generation did not move


def test_a_generation_that_cannot_be_written_undoes_the_seal(
    secrets: MailSecretStore, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unwritable(_home: Path) -> str:
        raise OSError("read-only file system")

    monkeypatch.setattr(setup_flow, "new_setup_generation", unwritable)
    with pytest.raises(MailSetupError) as raised:
        start(make_flows(secrets, home, Connector(gmail_server())))
    assert raised.value.code == "store_path_unsafe" and credential_files(secrets) == []
