"""Wizard Telegram ceremony and classified login/logout flows on Windows (C6-telegram).

Portable: real checked transactions, real MRKW wrap/unwrap, real MTC1/MTG1
crypto, the real C10b ``WindowsCustodySecretStore`` and archive, and the real
C5e capability predicates; only the native P-256 boundary, the token SID,
helper presence and the platform decisions are injected (the C10b/C5e seams).
Telegram is never contacted: login and revocation use a synthetic client.
Every refusal asserts native call accounting; key bytes never appear in an
assertion operand.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.extension.telegram import _windows_archive, hardening, secrets, service, store, tee
from mordred_hermes.extension.telegram.memory_guard import MemoryEncryptionRequired
from mordred_hermes.extension.telegram.windows_secrets import _DEFINITE, WindowsCustodySecretStore
from mordred_hermes.keyvault import _memory_storage, _seckey_helper, _windows_capability, wrap
from mordred_hermes.wizard import (
    _windows_gates,
    _windows_telegram,
    cli,
    encryption_cli,
    keyvault_windows_cli,
    telegram_cli,
    telegram_setup_cli,
)
from tests.test_windows_telegram_archive import KEY, _msg, held_in_thread
from tests.test_windows_telegram_custody import (  # noqa: F401
    SESSION,
    _value,
    custody_fixture,
    enroll,
    ops,
    sealed_path,
    telegram_fs,
    windows_store,
)
from tests.test_wizard_windows_memory import fs as fs
from tests.test_wizard_windows_memory import installed_runtime as installed_runtime
from tests.test_wizard_windows_memory import proof_env as proof_env
from tests.test_wizard_windows_memory import win as win

CEREMONY = "hermes-mordred keyvault native init --role telegram"
ACK_FLAG = "--acknowledge-machine-bound"
CAPABILITIES = (
    "memory_custody",
    "native_audit",
    "telegram_hardware",
    "file_vault",
    "env_config_workspace_seals",
    "recovery",
    "presence",
    "secret_store",
)
#: Prompt substrings the Windows flows ask (an unexpected prompt fails the test).
CEREMONY_PROMPT = "Windows Telegram custody key now?"
ACK_PROMPT = "Acknowledge the machine-bound Telegram custody"
MEMORY_PROMPT = "Turn on Windows memory encryption now?"
FORGET_PROMPT = "Type 'forget telegram'"
LOGIN_ANSWERS = [("api_id", "12345"), ("Phone number", "+810000"), ("Login code", "11111")]


class Answers:
    """Prompt-keyed answers; any prompt without a rule fails the test."""

    def __init__(self, rules):
        self.rules = list(rules)
        self.prompts: list[str] = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        for key, value in self.rules:
            if key in prompt:
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected prompt: {prompt!r}")

    def asked(self, key):
        return any(key in prompt for prompt in self.prompts)


class FakeClient:
    """Synthetic Telegram client: no network, no account."""

    def __init__(self):
        self.session = SESSION
        self.logged_out = False
        self.sign_ins: list[dict] = []

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def send_code_request(self, phone):
        assert phone == "+810000"

    async def sign_in(self, **kwargs):
        self.sign_ins.append(kwargs)
        return object()

    async def is_user_authorized(self):
        return True

    async def log_out(self):
        self.logged_out = True


class Factory:
    def __init__(self):
        self.client = FakeClient()
        self.calls = 0

    def __call__(self, api_id, api_hash, session, *, policy):
        self.calls += 1
        return self.client


@pytest.fixture
def wt(tg, monkeypatch):
    """Windows routing on any host over the C10b custody fixture."""
    c, home, backend = tg
    helper = str(home.parent / "bin" / "mordred-hermes-winkey.exe")
    monkeypatch.setattr(_windows_capability, "_platform", lambda: "win32")
    monkeypatch.setattr(_windows_gates, "host_platform", lambda: "win32")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: helper)
    monkeypatch.setattr(_memory_storage, "windows_memory_runtime_admitted", lambda executable=None: True)
    monkeypatch.setattr(c, "windows_backend", lambda: backend)
    monkeypatch.setattr(hardening, "harden_process", lambda: None)
    monkeypatch.setattr(_windows_telegram, "memory_active", lambda home=None: True)
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.save_session", lambda client: client.session)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv(telegram_cli.API_ID_ENV, raising=False)
    monkeypatch.delenv(telegram_cli.API_HASH_ENV, raising=False)
    return SimpleNamespace(custody=c, home=home, backend=backend, root=home / "mordred" / "telegram")


def generated(env) -> int:
    return ops(env.backend, "generate")


def role(env, name):
    with env.custody.windows_custody_session(env.home, backend=env.backend) as session:
        return session.role_status(name)


def seed(env, **overrides):
    """Memory, audit and telegram custody; sealed credentials with a session; an archive."""
    leases = enroll(env.custody, env.home, env.backend, "memory", "audit", "telegram")
    windows_store(env.home, env.backend).store(_value(store_key=KEY, **overrides))
    archive = store.ArchiveStore(KEY, env.root)
    archive.save_index(store.ArchiveIndex(account_label="me"))
    archive.append_messages(1, [_msg(1)])
    archive.append_messages(2, [_msg(2)])
    return leases


def segments(env):
    dialogs = env.root / "dialogs"
    return sorted(p.name for p in dialogs.iterdir() if p.name.endswith(".enc")) if dialogs.exists() else []


def tree(env):
    """Every data file under the profile's mordred directory with its digest.

    Skipped: permanent ``.mordred-fs.lock`` files (one may be held, a byte-range
    lock on Windows, or first created by a refused operation's checked lock
    acquisition) and the audit log, which records every unwrap by design.
    """
    base = env.home / "mordred"
    if not base.exists():
        return {}
    return {
        str(path.relative_to(base)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(base.rglob("*"))
        if path.is_file() and path.name != ".mordred-fs.lock" and "audit.log" not in path.name
    }


def memory_digest(env):
    with env.custody.windows_custody_session(env.home, backend=env.backend) as session:
        return hashlib.sha256(session.load_memory_key()).hexdigest()


def forbidden(prompt):
    raise AssertionError(f"no prompt expected: {prompt!r}")


def login_through(monkeypatch, factory):
    """Route setup's login through the real Windows login with a synthetic client."""
    real = telegram_cli.telegram_login
    seen: list[dict] = []

    def login(**kwargs):
        seen.append(dict(kwargs))
        return real(client_factory=factory, **kwargs)

    monkeypatch.setattr(telegram_cli, "telegram_login", login)
    return seen


# -----------------------------------------------------------------------------
# keyvault native init --role telegram
# -----------------------------------------------------------------------------
def test_native_init_enrolls_only_the_telegram_role_and_prints_the_notice(wt, capsys):
    assert cli.main(["keyvault", "native", "init", "--role", "telegram"]) == 0
    out = capsys.readouterr().out
    lease = role(wt, "telegram").current
    assert lease is not None
    assert f"telegram : enrolled now — generation {lease.generation}" in out
    assert lease.public_sha256 in out
    assert keyvault_windows_cli.CUSTODY_NOTICE in out
    assert "telegram setup" in out and "telegram login" in out
    assert role(wt, "memory").current is None and role(wt, "audit").current is None
    assert not wt.root.exists(), "enrollment is inert: no Telegram directory or credentials"
    assert generated(wt) == 1

    assert keyvault_windows_cli.native_init(home=wt.home, roles=["telegram"]) == 0
    assert "telegram : already enrolled (unchanged)" in capsys.readouterr().out
    assert generated(wt) == 1 and role(wt, "telegram").current == lease


def test_native_init_telegram_refuses_without_helper_before_any_write(wt, monkeypatch, capsys):
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    assert keyvault_windows_cli.native_init(home=wt.home, roles=["telegram"]) == 1
    err = capsys.readouterr().err
    assert "telegram custody refused (helper-missing)" in err and "keyvault enable-winkey" in err
    assert wt.backend.calls == [] and not (wt.home / "mordred").exists()


# -----------------------------------------------------------------------------
# telegram setup
# -----------------------------------------------------------------------------
def test_setup_on_a_fresh_home_runs_the_ceremony_then_login_with_acknowledgement(wt, monkeypatch, capsys):
    factory = Factory()
    seen = login_through(monkeypatch, factory)
    answers = Answers(
        [
            (CEREMONY_PROMPT, "y"),
            (ACK_PROMPT, "y"),
            *LOGIN_ANSWERS,
            ("Choice", "1"),
            ("Use this scope", "y"),
            ("Import now?", "n"),
        ]
    )
    hidden = Answers([("api_hash", "cd" * 16), ("Venice API key", "VENICE-NEW")])
    assert telegram_setup_cli.telegram_setup(input_fn=answers, secret_fn=hidden) == 0
    out = capsys.readouterr().out
    assert CEREMONY in out
    assert keyvault_windows_cli.CUSTODY_NOTICE in out and _windows_telegram.TELEGRAM_NOTICE in out
    keys = (CEREMONY_PROMPT, ACK_PROMPT, "api_id")
    first = [next(i for i, p in enumerate(answers.prompts) if key in p) for key in keys]
    assert first == sorted(first), "ceremony, then the acknowledgement, then the first login prompt"
    assert seen and seen[0].get("acknowledge_machine_bound") is False
    value = windows_store(wt.home, wt.backend).load()
    assert value.session == SESSION and value.api_id == 12345 and value.venice_api_key == "VENICE-NEW"
    flags = windows_store(wt.home, wt.backend).flags()
    assert flags["logged_in"] is True and flags["sync_scope"]["include_channels"] is False
    assert generated(wt) == 1, "only the explicit ceremony generates a key"
    assert role(wt, "memory").current is None and role(wt, "audit").current is None
    assert telegram_setup_cli.WINDOWS_DONE in out
    assert "not available on Windows yet" in out and "C11" in out
    assert "Restart the Hermes gateway" not in out and "Browser extension: ⚙" not in out


def test_setup_on_an_enrolled_home_skips_the_ceremony(wt, monkeypatch):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    login_through(monkeypatch, Factory())
    answers = Answers([*LOGIN_ANSWERS, ("Choice", "2"), ("Local endpoint", "http://127.0.0.1:11434/v1")])
    answers.rules += [("Model name", "qwen"), ("Use this scope", "n"), ("Import now?", "n")]
    hidden = Answers([("api_hash", "cd" * 16)])
    rc = telegram_setup_cli.telegram_setup(input_fn=answers, secret_fn=hidden, acknowledge_machine_bound=True)
    assert rc == 0
    assert not answers.asked(CEREMONY_PROMPT) and not answers.asked(ACK_PROMPT)
    assert generated(wt) == 1
    assert windows_store(wt.home, wt.backend).load().local_model == "qwen"


def test_setup_declining_the_ceremony_stops_without_generating(wt, capsys):
    answers = Answers([(CEREMONY_PROMPT, "n")])
    assert telegram_setup_cli.telegram_setup(input_fn=answers, secret_fn=forbidden) == 1
    captured = capsys.readouterr()
    assert CEREMONY in captured.out and "setup stopped" in captured.err
    assert wt.backend.calls == [] and not (wt.home / "mordred").exists()


def test_setup_ceremony_prompt_defaults_to_no_and_survives_eof(wt):
    for answer in ("", EOFError()):
        answers = Answers([(CEREMONY_PROMPT, answer)])
        assert telegram_setup_cli.telegram_setup(input_fn=answers, secret_fn=forbidden) == 1
    assert wt.backend.calls == []


def test_setup_refuses_a_copied_home_as_broken_without_generating(wt, monkeypatch, capsys):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    copied = wt.home.parent / "copied"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("windows-custody.json", (wt.home / "mordred" / "windows-custody.json").read_bytes())
    monkeypatch.setenv("HERMES_HOME", str(copied))
    before = tree(SimpleNamespace(home=copied))
    calls = list(wt.backend.calls)
    assert telegram_setup_cli.telegram_setup(input_fn=forbidden, secret_fn=forbidden) == 1
    err = capsys.readouterr().err
    assert "(custody-broken)" in err and "never adopted" in err
    assert wt.backend.calls == calls and tree(SimpleNamespace(home=copied)) == before


def test_setup_refuses_an_orphan_journal_as_broken(wt, capsys):
    with open_private_directory(wt.home / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("windows-telegram.pending.json", b"{}")
    before = tree(wt)
    assert telegram_setup_cli.telegram_setup(input_fn=forbidden, secret_fn=forbidden) == 1
    assert "(custody-broken)" in capsys.readouterr().err
    assert wt.backend.calls == [] and tree(wt) == before


def test_setup_without_helper_refuses_with_the_winkey_remedy(wt, monkeypatch, capsys):
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    assert telegram_setup_cli.telegram_setup(input_fn=forbidden, secret_fn=forbidden) == 1
    err = capsys.readouterr().err
    assert "(helper-missing)" in err and "keyvault enable-winkey" in err
    assert wt.backend.calls == []


def test_setup_stops_before_login_without_the_acknowledgement(wt, monkeypatch, capsys):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    factory = Factory()
    login_through(monkeypatch, factory)
    calls = list(wt.backend.calls)
    assert telegram_setup_cli.telegram_setup(input_fn=Answers([(ACK_PROMPT, "n")]), secret_fn=forbidden) == 1
    assert ACK_FLAG in capsys.readouterr().err
    assert factory.calls == 0 and wt.backend.calls == calls
    assert not sealed_path(wt.home).exists()


def test_setup_memory_step_uses_the_windows_memory_enable(wt, monkeypatch, capsys):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    state = {"active": False, "enabled": []}
    monkeypatch.setattr(_windows_telegram, "memory_active", lambda home=None: state["active"])

    def enable(*, home, force_runtime_unverified=False):
        state["enabled"].append(home)
        state["active"] = True
        return 0

    def posix_path(*args, **kwargs):
        raise AssertionError("the macOS/Linux memory path was used on Windows")

    from mordred_hermes.wizard import _windows_memory

    monkeypatch.setattr(_windows_memory, "enable", enable)
    monkeypatch.setattr(encryption_cli, "_dispatch", posix_path)
    assert telegram_setup_cli.telegram_setup(input_fn=Answers([(MEMORY_PROMPT, "n")]), secret_fn=forbidden) == 1
    assert "memory encryption is required" in capsys.readouterr().err and state["enabled"] == []
    answers = Answers([(MEMORY_PROMPT, "y"), (ACK_PROMPT, "n")])
    assert telegram_setup_cli.telegram_setup(input_fn=answers, secret_fn=forbidden) == 1
    assert state["enabled"] == [wt.home]


def test_setup_memory_step_runs_the_real_c6_windows_enable(win, monkeypatch, capsys):
    env = win
    monkeypatch.setattr(_windows_archive, "open_optional_private_directory", cio.open_optional_private_directory)
    monkeypatch.setattr(store, "_platform", lambda: "win32")
    monkeypatch.setattr(hardening, "harden_process", lambda: None)
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.telethon_available", lambda: True)

    def posix_path(*args, **kwargs):
        raise AssertionError("the macOS/Linux memory path was used on Windows")

    monkeypatch.setattr(encryption_cli, "_dispatch", posix_path)
    assert _windows_telegram.memory_active(env.home) is False
    answers = Answers([(CEREMONY_PROMPT, "y"), (MEMORY_PROMPT, "y"), (ACK_PROMPT, "n")])
    assert telegram_setup_cli.telegram_setup(input_fn=answers, secret_fn=forbidden) == 1
    captured = capsys.readouterr()
    assert "Agent-memory encryption enabled on Windows" in captured.out
    assert ACK_FLAG in captured.err, "setup stopped at the acknowledgement, after the real memory enable"
    assert _windows_telegram.memory_active(env.home) is True
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        assert owner.role_status("telegram").current is not None
        assert owner.memory_state().lease is not None and owner.role_status("audit").current is None
    assert sum(1 for op, _ in env.backend.calls if op == "generate") == 2


# -----------------------------------------------------------------------------
# telegram login
# -----------------------------------------------------------------------------
def test_login_refuses_without_enrollment_before_any_backend_call(wt, capsys):
    factory = Factory()
    rc = telegram_cli.telegram_login(
        input_fn=forbidden, secret_fn=forbidden, client_factory=factory, acknowledge_machine_bound=True
    )
    assert rc == 1
    assert CEREMONY in capsys.readouterr().err
    assert wt.backend.calls == [] and factory.calls == 0 and not wt.root.exists()


@pytest.mark.parametrize("answer", ["n", "", EOFError()])
def test_login_refuses_without_acknowledgement_before_any_backend_call(wt, capsys, answer):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    windows_store(wt.home, wt.backend).store(_value(session=None))
    calls = list(wt.backend.calls)
    factory = Factory()
    answers = Answers([(ACK_PROMPT, answer)])
    rc = telegram_cli.telegram_login(input_fn=answers, secret_fn=forbidden, client_factory=factory)
    assert rc == 1
    captured = capsys.readouterr()
    assert _windows_telegram.disclosure() in captured.out and _windows_telegram.TELEGRAM_NOTICE in captured.out
    assert "There is no per-use presence and no portable recovery" in captured.out
    assert "Disable memory encryption" not in captured.out, "the memory-only sentence is not part of the disclosure"
    assert ACK_FLAG in captured.err
    assert wt.backend.calls == calls, "nothing unsealed before the acknowledgement"
    assert factory.calls == 0


def test_login_after_acknowledgement_seals_with_require_presence_false(wt, monkeypatch, capsys):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    requested: list[dict] = []
    real = WindowsCustodySecretStore.ensure_key

    def spy(self, **kwargs):
        requested.append(kwargs)
        return real(self, **kwargs)

    monkeypatch.setattr(WindowsCustodySecretStore, "ensure_key", spy)
    factory = Factory()
    answers = Answers([(ACK_PROMPT, "y"), *LOGIN_ANSWERS])
    rc = telegram_cli.telegram_login(
        input_fn=answers, secret_fn=Answers([("api_hash", "cd" * 16)]), client_factory=factory
    )
    assert rc == 0
    assert requested == [{"require_presence": False}]
    assert "no per-use presence" in capsys.readouterr().out
    value = windows_store(wt.home, wt.backend).load()
    assert value.session == SESSION and value.api_hash == "cd" * 16
    assert generated(wt) == 1


def test_login_flag_acknowledges_without_prompting(wt):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    rc = telegram_cli.telegram_login(
        input_fn=Answers(LOGIN_ANSWERS),
        secret_fn=Answers([("api_hash", "cd" * 16)]),
        client_factory=Factory(),
        acknowledge_machine_bound=True,
    )
    assert rc == 0 and windows_store(wt.home, wt.backend).load().session == SESSION


def test_login_wipes_an_orphaned_archive_through_checked_storage(wt, monkeypatch, capsys):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    orphan = store.ArchiveStore(b"\x09" * 32, wt.root)
    orphan.save_index(store.ArchiveIndex(account_label="old"))

    def raw_scan(*args, **kwargs):
        raise AssertionError("raw directory scan of the Telegram archive on Windows")

    monkeypatch.setattr(Path, "rglob", raw_scan)
    monkeypatch.setattr(Path, "glob", raw_scan)
    rc = telegram_cli.telegram_login(
        input_fn=Answers(LOGIN_ANSWERS),
        secret_fn=Answers([("api_hash", "cd" * 16)]),
        client_factory=Factory(),
        acknowledge_machine_bound=True,
    )
    assert rc == 0
    assert "undecryptable archive" in capsys.readouterr().err
    assert not (wt.root / "index.enc").exists()


def test_cli_flags_reach_login_and_setup(wt, monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(telegram_cli, "telegram_login", lambda **kw: seen.append(("login", kw)) or 0)
    monkeypatch.setattr(telegram_setup_cli, "telegram_setup", lambda **kw: seen.append(("setup", kw)) or 0)
    assert cli.main(["telegram", "login", ACK_FLAG]) == 0
    assert cli.main(["telegram", "setup", ACK_FLAG]) == 0
    assert cli.main(["telegram", "login"]) == 0
    assert [(name, kw["acknowledge_machine_bound"]) for name, kw in seen] == [
        ("login", True),
        ("setup", True),
        ("login", False),
    ]


# -----------------------------------------------------------------------------
# Classified codes
# -----------------------------------------------------------------------------
CODES = {
    "telegram_not_enrolled": CEREMONY,
    "machine_bound_not_acknowledged": ACK_FLAG,
    "presence_unsupported": ACK_FLAG,
    "custody_unsafe": "never repairs ACLs",
    "custody_uncertain": "no `keyvault native reconcile` command yet",
    "custody_broken": "never adopted",
    "tee_unavailable": "keyvault enable-winkey",
    "tee_auth_cancelled": "retry the command",
    "secrets_corrupt": "telegram logout --forget",
    "store_path_unsafe": "never repairs ACLs",
    "store_write_uncertain": "telegram doctor",
    "store_unavailable": "telegram doctor",
    "store_missing": "retry",
    "store_io": "retry",
    "store_busy": "retry",
    "store_undecryptable": "`hermes-mordred telegram logout --forget`, then run `hermes-mordred telegram setup`",
    "credentials_without_custody": "`hermes-mordred telegram logout --forget`",
    "store_key_invalid": "telegram logout --forget",
    "sync_in_progress": "nothing was changed",
    "vault_unavailable": "excluded on Windows",
    "vault_not_initialized": "excluded on Windows",
    "memory_encryption_required": "hermes-mordred encryption enable memory",
}


@pytest.mark.parametrize(("code", "remedy"), sorted(CODES.items()))
def test_every_classified_code_has_a_windows_message_with_a_remedy(wt, capsys, code, remedy):
    assert telegram_cli._report(code) == 1
    err = capsys.readouterr().err
    assert remedy in err
    assert "telegram operation failed" not in err
    assert "Secure Enclave" not in err and "Touch ID" not in err and "enable-se" not in err
    assert "enable env" not in err


def test_the_message_table_covers_every_store_and_custody_code(wt):
    from mordred_hermes._private_fs import PrivateFSError

    produced = set(_DEFINITE.values()) | {"custody_unsafe", "custody_uncertain", "custody_broken"}
    for reason in ("busy", "unsafe", "access_denied", "unsupported", "missing", "io", "exists"):
        for state in ("not_committed", "uncertain"):
            produced.add(store._store_error(PrivateFSError(reason, "op", commit_state=state)).code)
            produced.add(store._store_error(PrivateFSError(reason, "op", commit_state=state), lock=True).code)
    assert produced - set(CODES) == set()


def test_classified_store_errors_reach_the_windows_message(wt, capsys):
    assert telegram_cli.telegram_venice(model="m", secret_fn=forbidden) == 1
    assert CEREMONY in capsys.readouterr().err
    assert wt.backend.calls == []


def test_posix_messages_and_store_are_unchanged(monkeypatch, capsys):
    monkeypatch.setattr(_windows_gates, "host_platform", lambda: "darwin")
    monkeypatch.setattr(telegram_cli, "sys", SimpleNamespace(platform="darwin", stderr=__import__("sys").stderr))
    assert isinstance(telegram_cli._secret_store(), tee.TeeSecretStore)
    telegram_cli._report("tee_unavailable")
    telegram_cli._report("memory_encryption_required")
    err = capsys.readouterr().err
    assert "Secure Enclave" in err and "enable-se" in err and "enable env" in err
    assert _windows_telegram.routed() is False


# -----------------------------------------------------------------------------
# venice / local-llm / sync / status
# -----------------------------------------------------------------------------
def test_venice_and_local_llm_use_the_custody_store_without_presence(wt, monkeypatch):
    enroll(wt.custody, wt.home, wt.backend, "telegram")

    def presence(self, **kwargs):
        raise AssertionError("venice/local-llm must not request or skip presence on Windows")

    monkeypatch.setattr(WindowsCustodySecretStore, "ensure_key", presence)
    assert telegram_cli.telegram_venice(model="qwen3", secret_fn=lambda _p: "VKEY") == 0
    assert telegram_cli.telegram_local_llm(endpoint="http://127.0.0.1:11434/v1", model="qwen") == 0
    value = windows_store(wt.home, wt.backend).load()
    assert value.venice_api_key == "VKEY" and value.backend == "local" and value.local_model == "qwen"
    assert generated(wt) == 1


def test_sync_routes_the_windows_memory_guard(wt, monkeypatch):
    built: list[dict] = []

    class Recorder:
        _secrets = None

        def __init__(self, **kwargs):
            built.append(kwargs)

        def sync_options(self, given):
            from mordred_hermes.extension.telegram.client import SyncOptions

            return SyncOptions()

    async def run(svc, options, *, poll=1.0):
        return 0

    monkeypatch.setattr(service, "TelegramService", Recorder)
    monkeypatch.setattr(telegram_cli, "_run_sync", run)
    assert telegram_cli.telegram_sync() == 0
    assert built == [{"memory_guard": _windows_telegram.memory_guard}]


def test_windows_memory_guard_never_uses_the_posix_marker_check(wt, monkeypatch):
    def posix(*args, **kwargs):
        raise AssertionError("the macOS/Linux memory marker check was used on Windows")

    monkeypatch.setattr("mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", posix)
    monkeypatch.setattr(_windows_telegram, "memory_active", lambda home=None: False)
    with pytest.raises(MemoryEncryptionRequired):
        _windows_telegram.memory_guard()
    assert telegram_cli._login_preflight(lambda: True) == "memory_encryption_required"
    monkeypatch.setattr(_windows_telegram, "memory_active", lambda home=None: True)
    _windows_telegram.memory_guard()
    assert telegram_cli._login_preflight(lambda: True) is None


# -----------------------------------------------------------------------------
# telegram logout / logout --forget
# -----------------------------------------------------------------------------
def test_logout_keeps_the_archive_credentials_and_role(wt, capsys):
    leases = seed(wt)
    archive_before = {name: digest for name, digest in tree(wt).items() if name.endswith(".enc")}
    factory = Factory()
    assert telegram_cli.telegram_logout(store=None, client_factory=factory, input_fn=forbidden) == 0
    out = capsys.readouterr().out
    assert factory.client.logged_out and "Revoked the session" in out
    assert "Logged out. The encrypted archive is kept (use --forget to delete it)." in out
    assert {name: digest for name, digest in tree(wt).items() if name.endswith(".enc")} == archive_before
    assert (wt.root / "index.enc").exists() and len(segments(wt)) == 2
    assert store.ArchiveStore(KEY, wt.root).load_index().account_label == "me"
    value = windows_store(wt.home, wt.backend).load()
    assert value is not None and value.session is None and value.store_key == KEY
    with wt.custody.windows_custody_session(wt.home, backend=wt.backend) as session:
        session.validate_lease(leases["telegram"])
    assert ops(wt.backend, "delete") == 0 and generated(wt) == 3


def test_forget_requires_the_typed_confirmation(wt, capsys):
    seed(wt)
    before = tree(wt)
    factory = Factory()
    for answer in ("yes", "forget", "", EOFError()):
        rc = telegram_cli.telegram_logout(
            forget=True, client_factory=factory, input_fn=Answers([(FORGET_PROMPT, answer)])
        )
        assert rc == 1
    out = capsys.readouterr().out
    assert "nothing was changed" in out and "Then the stored Telegram session is revoked" in out
    assert factory.calls == 0 and tree(wt) == before
    assert ops(wt.backend, "delete") == 0 and generated(wt) == 3, "only the load ran before the refusal"


def audit_roundtrip(env, lease, blob=None):
    """Wrap a synthetic data key to the audit lease, or unwrap ``blob`` and return its digest."""
    synthetic = b"\x11" * 32
    with env.custody.windows_custody_session(env.home, backend=env.backend) as session:
        backend = session.backend_for(lease)
    if blob is None:
        return wrap.wrap_dek(synthetic, lease.key_id, backend=backend, native_key_id=lease.native_key_id)
    dek = wrap.unwrap_dek(
        blob, lease.key_id, audit_sink=lambda entry: None, backend=backend, native_key_id=lease.native_key_id
    )
    return hashlib.sha256(dek).digest() == hashlib.sha256(synthetic).digest()


def test_forget_deletes_credentials_archive_and_role_and_keeps_memory_and_audit(wt, capsys):
    leases = seed(wt)
    memory = memory_digest(wt)
    audit_blob = audit_roundtrip(wt, leases["audit"])
    factory = Factory()
    rc = telegram_cli.telegram_logout(
        forget=True, client_factory=factory, input_fn=Answers([(FORGET_PROMPT, "forget telegram")])
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert factory.client.logged_out
    assert "credentials.sealed" in out and "local encrypted archive" in out
    assert f"generation(s) {leases['telegram'].generation}" in out
    assert "memory and audit custody" in out.casefold()
    assert not sealed_path(wt.home).exists() and not (wt.root / "credentials.meta.json").exists()
    assert not (wt.root / "index.enc").exists() and segments(wt) == []
    assert role(wt, "telegram") == wt.custody.RoleStatus("telegram", None, (), False)
    with wt.custody.windows_custody_session(wt.home, backend=wt.backend) as session:
        session.validate_lease(leases["memory"])
        session.validate_lease(leases["audit"])
        session.backend_for(leases["audit"])
    assert memory_digest(wt) == memory, "memory custody stays decryptable"
    assert audit_roundtrip(wt, leases["audit"], audit_blob) is True, "audit custody stays decryptable"
    deleted = [key_id for op, key_id in wt.backend.calls if op == "delete"]
    assert deleted == [leases["telegram"].native_key_id]
    assert generated(wt) == 3


def test_forget_with_undecryptable_credentials_still_deletes_after_confirmation(wt, capsys):
    seed(wt)
    raw = bytearray(sealed_path(wt.home).read_bytes())
    raw[-1] ^= 0x01
    with open_private_directory(wt.root) as directory, directory.transaction() as tx:
        tx.replace_bytes("credentials.sealed", bytes(raw))
    factory = Factory()
    rc = telegram_cli.telegram_logout(
        forget=True, client_factory=factory, input_fn=Answers([(FORGET_PROMPT, "forget telegram")])
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "Settings → Devices" in captured.err and factory.calls == 0
    assert not sealed_path(wt.home).exists() and role(wt, "telegram").current is None


def test_logout_and_forget_refuse_while_a_sync_holds_the_lock(wt, capsys):
    seed(wt)
    factory = Factory()
    with held_in_thread(wt.root):
        before, calls = tree(wt), list(wt.backend.calls)
        assert telegram_cli.telegram_logout(client_factory=factory, input_fn=forbidden) == 1
        assert telegram_cli.telegram_logout(forget=True, client_factory=factory, input_fn=forbidden) == 1
        assert tree(wt) == before and wt.backend.calls == calls
    err = capsys.readouterr().err
    assert err.count("another Telegram sync is running") == 2
    assert factory.calls == 0


def test_forget_refuses_a_missing_helper_before_revoking(wt, monkeypatch, capsys):
    seed(wt)
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    before, calls = tree(wt), list(wt.backend.calls)
    factory = Factory()
    assert telegram_cli.telegram_logout(forget=True, client_factory=factory, input_fn=forbidden) == 1
    assert "keyvault enable-winkey" in capsys.readouterr().err
    assert factory.calls == 0 and tree(wt) == before and wt.backend.calls == calls


def test_ambiguous_forget_deletion_reports_the_reconcile_gap(wt, monkeypatch, capsys):
    seed(wt)
    real_delete = wt.backend.delete_enclave_key

    def lost(key_id):
        real_delete(key_id)
        raise RuntimeError("native deletion result lost")

    monkeypatch.setattr(wt.backend, "delete_enclave_key", lost)
    leases = role(wt, "telegram")
    confirm = Answers([(FORGET_PROMPT, "forget telegram")])
    factory = Factory()
    assert telegram_cli.telegram_logout(forget=True, client_factory=factory, input_fn=confirm) == 1
    captured = capsys.readouterr()
    assert "custody-uncertain" in captured.err and "no `keyvault native reconcile` command yet" in captured.err
    assert "nothing is deleted" not in captured.err
    deleted, _, remaining = captured.out.partition("Still present:")
    assert "Deleted:" in deleted and "credentials.sealed" in deleted and "local encrypted archive" in deleted
    assert leases.current.generation in remaining and "deletion journal is kept" in remaining
    assert factory.client.logged_out, "the in-memory session is revoked once the credentials are gone"
    assert not sealed_path(wt.home).exists() and not (wt.root / "index.enc").exists()
    journal = wt.home / "mordred" / "windows-telegram.pending.json"
    assert journal.exists()
    monkeypatch.setattr(wt.backend, "delete_enclave_key", real_delete)
    assert telegram_cli.telegram_logout(forget=True, client_factory=Factory(), input_fn=confirm) == 1
    assert journal.exists()


def test_forget_on_an_unconfigured_profile_deletes_nothing_without_prompting(wt, capsys):
    assert telegram_cli.telegram_logout(forget=True, client_factory=Factory(), input_fn=forbidden) == 0
    assert "Nothing to delete" in capsys.readouterr().out
    assert wt.backend.calls == [] and not (wt.home / "mordred").exists()


class FailingClient(FakeClient):
    """Revocation that cannot reach Telegram; records whether the local credentials were already gone."""

    def __init__(self, sealed):
        super().__init__()
        self.sealed = sealed
        self.credentials_at_revoke: bool | None = None

    async def connect(self):
        self.credentials_at_revoke = self.sealed.exists()
        raise OSError("network unreachable")


def test_forget_preflight_refusal_leaves_credentials_archive_and_session_untouched(wt, capsys):
    seed(wt)
    # A malformed memory journal: the telegram capability is fine, the C10b forget preflight refuses.
    with open_private_directory(wt.home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("windows-memory.pending.json", b"{}")
    before = tree(wt)
    factory = Factory()
    confirm = Answers([(FORGET_PROMPT, "forget telegram")])
    assert telegram_cli.telegram_logout(forget=True, client_factory=factory, input_fn=confirm) == 1
    captured = capsys.readouterr()
    assert "(custody-broken)" in captured.err
    assert "Nothing was deleted." in captured.out and "Still present:" in captured.out
    assert factory.calls == 0, "the live session is not revoked when nothing was deleted"
    assert tree(wt) == before and ops(wt.backend, "delete") == 0
    assert windows_store(wt.home, wt.backend).load().session == SESSION


def test_forget_revokes_only_after_local_deletion_and_warns_when_telegram_is_unreachable(wt, capsys):
    seed(wt)
    client = FailingClient(sealed_path(wt.home))
    confirm = Answers([(FORGET_PROMPT, "forget telegram")])
    rc = telegram_cli.telegram_logout(forget=True, client_factory=lambda *a, **k: client, input_fn=confirm)
    assert rc == 0
    captured = capsys.readouterr()
    assert client.credentials_at_revoke is False, "revocation runs after the local deletion"
    assert "could not reach Telegram" in captured.err and "Settings → Devices" in captured.err
    assert "Deleted:" in captured.out and "credentials.sealed" in captured.out
    assert not sealed_path(wt.home).exists() and role(wt, "telegram").current is None


def orphan_credentials(env):
    """Sealed credentials whose telegram role was reset elsewhere (no key can ever open them)."""
    seed(env)
    with env.custody.windows_custody_session(env.home, backend=env.backend) as session:
        session.reset_role("telegram", erase_authorized=True)
    assert sealed_path(env.home).exists() and role(env, "telegram").current is None


def test_credentials_without_a_role_point_to_forget_and_setup_offers_no_ceremony(wt, capsys):
    orphan_credentials(wt)
    before, calls = tree(wt), list(wt.backend.calls)
    factory = Factory()
    assert telegram_cli.telegram_logout(client_factory=factory, input_fn=forbidden) == 1
    assert (
        telegram_cli.telegram_login(
            input_fn=forbidden, secret_fn=forbidden, client_factory=factory, acknowledge_machine_bound=True
        )
        == 1
    )
    assert telegram_cli.telegram_venice(model="m", secret_fn=forbidden) == 1
    assert telegram_setup_cli.telegram_setup(input_fn=forbidden, secret_fn=forbidden) == 1
    err = capsys.readouterr().err
    assert err.count("(credentials_without_custody)") == 4 and CEREMONY not in err
    assert factory.calls == 0 and tree(wt) == before and wt.backend.calls == calls
    assert generated(wt) == 3, "no ceremony was offered or run"


def test_forget_deletes_credentials_without_a_role_after_warning_first(wt, capsys):
    orphan_credentials(wt)
    factory = Factory()
    seen: list[str] = []

    def confirm(prompt):
        seen.append(capsys.readouterr().err)
        assert FORGET_PROMPT in prompt
        return "forget telegram"

    assert telegram_cli.telegram_logout(forget=True, client_factory=factory, input_fn=confirm) == 0
    assert "Settings → Devices" in seen[0], "the skipped-revocation warning precedes the confirmation"
    assert "credentials.sealed" in capsys.readouterr().out
    assert factory.calls == 0 and not sealed_path(wt.home).exists() and not (wt.root / "index.enc").exists()


def test_logout_and_forget_refuse_broken_custody_before_anything(wt, capsys):
    seed(wt)
    with open_private_directory(wt.home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("windows-telegram.pending.json", b"{}")
    before, calls = tree(wt), list(wt.backend.calls)
    factory = Factory()
    assert telegram_cli.telegram_logout(client_factory=factory, input_fn=forbidden) == 1
    assert telegram_cli.telegram_logout(forget=True, client_factory=factory, input_fn=forbidden) == 1
    assert capsys.readouterr().err.count("(custody-broken)") == 2
    assert factory.calls == 0 and tree(wt) == before and wt.backend.calls == calls


def test_logout_and_forget_refuse_an_unresolved_telegram_journal(wt, monkeypatch, capsys):
    seed(wt)

    def denied(*args, **kwargs):
        raise wt.custody.CustodyError("native creation failed")

    monkeypatch.setattr(wt.backend, "generate_enclave_key", denied)
    with (
        pytest.raises(wt.custody.CustodyError),
        wt.custody.windows_custody_session(wt.home, backend=wt.backend) as session,
    ):
        session.enroll_role("telegram", retain_current=True)
    assert (wt.home / "mordred" / "windows-telegram.pending.json").exists()
    before, calls = tree(wt), list(wt.backend.calls)
    factory = Factory()
    assert telegram_cli.telegram_logout(client_factory=factory, input_fn=forbidden) == 1
    assert telegram_cli.telegram_logout(forget=True, client_factory=factory, input_fn=forbidden) == 1
    assert capsys.readouterr().err.count("(custody-uncertain)") == 2
    assert factory.calls == 0 and tree(wt) == before and wt.backend.calls == calls


def test_login_wipes_orphaned_segments_without_an_index_through_checked_storage(wt, monkeypatch, capsys):
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    orphan = store.ArchiveStore(b"\x09" * 32, wt.root)
    orphan.save_index(store.ArchiveIndex(account_label="old"))
    orphan.append_messages(1, [_msg(1)])
    with open_private_directory(wt.root) as directory, directory.transaction() as tx:
        tx.delete_file("index.enc", expected_identity=tx.stat("index.enc").identity)
    assert segments(wt) and not (wt.root / "index.enc").exists()

    def raw_scan(*args, **kwargs):
        raise AssertionError("raw directory scan of the Telegram archive on Windows")

    monkeypatch.setattr(Path, "rglob", raw_scan)
    monkeypatch.setattr(Path, "glob", raw_scan)
    rc = telegram_cli.telegram_login(
        input_fn=Answers(LOGIN_ANSWERS),
        secret_fn=Answers([("api_hash", "cd" * 16)]),
        client_factory=Factory(),
        acknowledge_machine_bound=True,
    )
    assert rc == 0 and "undecryptable archive" in capsys.readouterr().err
    assert segments(wt) == []


def test_cli_logout_forget_routes_to_the_typed_confirmation(wt, monkeypatch, capsys):
    seed(wt)
    monkeypatch.setattr("builtins.input", Answers([(FORGET_PROMPT, "no")]))
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.build_client", Factory())
    assert cli.main(["telegram", "logout", "--forget"]) == 1
    assert sealed_path(wt.home).exists()


# -----------------------------------------------------------------------------
# telegram doctor
# -----------------------------------------------------------------------------
def _quiet_external_checks(monkeypatch):
    monkeypatch.setattr(
        telegram_setup_cli, "_check_telethon", lambda: telegram_setup_cli.Check("telethon", True, "installed")
    )
    monkeypatch.setattr(
        telegram_setup_cli, "_check_hermes", lambda: telegram_setup_cli.Check("hermes_integration", True, "x")
    )


def _forbid_native(monkeypatch, env):
    def tripwire(*args, **kwargs):
        raise AssertionError("doctor reached a native backend, wrap or unwrap")

    monkeypatch.setattr(env.custody, "windows_backend", tripwire)
    monkeypatch.setattr(wrap, "unwrap_dek", tripwire)
    monkeypatch.setattr(wrap, "wrap_dek", tripwire)


def test_doctor_reports_each_capability_without_unwrap_or_native_calls(wt, monkeypatch, capsys):
    leases = seed(wt, venice_model="m")
    _quiet_external_checks(monkeypatch)
    _forbid_native(monkeypatch, wt)

    def raw_scan(*args, **kwargs):
        raise AssertionError("raw directory scan of the Telegram archive on Windows")

    monkeypatch.setattr(Path, "rglob", raw_scan)
    monkeypatch.setattr(Path, "glob", raw_scan)
    calls = list(wt.backend.calls)
    assert telegram_setup_cli.telegram_doctor(as_json=True) == 0
    report = {row["name"]: row for row in json.loads(capsys.readouterr().out)}
    for name in ("telethon", "telegram_custody", "hardware", "memory_encryption", "login", "privacy_llm", "archive"):
        assert report[name]["ok"] is True, name
    assert "device hardware" not in report["login"]["detail"]
    assert "Windows CNG Telegram custody key" in report["login"]["detail"]
    assert leases["telegram"].generation in report["telegram_custody"]["detail"]
    assert leases["telegram"].public_sha256 in report["telegram_custody"]["detail"]
    capability_rows = [name for name in report if name.startswith("capability.")]
    assert capability_rows == [f"capability.{name}" for name in CAPABILITIES]
    presence = report["capability.presence"]
    assert presence["ok"] is False and "excluded on Windows" in presence["detail"]
    assert report["capability.telegram_hardware"]["ok"] is True
    assert wt.backend.calls == calls

    assert telegram_setup_cli.telegram_doctor() == 0
    text = capsys.readouterr().out
    assert "per-use presence: excluded on Windows (excluded-on-windows)" in text
    assert "Telegram custody: supported, available (enrolled)" in text
    assert "ready" not in text.casefold()


def test_doctor_on_a_fresh_home_points_to_the_ceremony(wt, monkeypatch, capsys):
    _quiet_external_checks(monkeypatch)
    _forbid_native(monkeypatch, wt)
    assert telegram_setup_cli.telegram_doctor(as_json=True) == 1
    report = {row["name"]: row for row in json.loads(capsys.readouterr().out)}
    assert report["telegram_custody"]["ok"] is False and report["telegram_custody"]["fix"] == CEREMONY
    assert report["login"]["ok"] is False and report["archive"]["ok"] is False
    assert wt.backend.calls == [] and not (wt.home / "mordred").exists()


def test_doctor_reports_unsafe_custody_as_a_classified_reason(wt, monkeypatch, capsys):
    _quiet_external_checks(monkeypatch)
    enroll(wt.custody, wt.home, wt.backend, "telegram")
    with open_private_directory(wt.home / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("windows-telegram.pending.json", b"{}")
    assert telegram_setup_cli.telegram_doctor(as_json=True) == 1
    report = {row["name"]: row for row in json.loads(capsys.readouterr().out)}
    assert "(custody-broken)" in report["telegram_custody"]["detail"]
    assert "never adopted" in report["telegram_custody"]["fix"]


# -----------------------------------------------------------------------------
# migrate-tee and other Enclave/TEE-only verbs
# -----------------------------------------------------------------------------
def test_migrate_tee_refuses_before_any_access(wt, monkeypatch, capsys):
    def tripwire(*args, **kwargs):
        raise AssertionError("migrate-tee touched a credential store on Windows")

    monkeypatch.setattr(secrets.VaultSecretStore, "__init__", tripwire)
    monkeypatch.setattr(tee.TeeSecretStore, "__init__", tripwire)
    monkeypatch.setattr(WindowsCustodySecretStore, "__init__", tripwire)
    monkeypatch.setattr(telegram_cli, "_secret_store", tripwire)
    assert telegram_cli.telegram_migrate_tee() == 1
    assert cli.main(["telegram", "migrate-tee"]) == 1
    assert cli.main(["telegram", "migrate-tee", "--no-touch-id"]) == 1
    err = capsys.readouterr().err
    assert err.count("file_vault is excluded on Windows") == 3
    assert wt.backend.calls == [] and not (wt.home / "mordred").exists()
