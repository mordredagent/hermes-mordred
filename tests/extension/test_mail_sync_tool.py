"""Hermes tool ``mordred_mail_sync``: strict arguments, gates, counts-only result, deadlines, cancellation."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.activity import _gate
from mordred_hermes.extension.telegram import hermes_tools, mail_tool
from mordred_hermes.imports.mail import imap_sync, secrets
from mordred_hermes.imports.mail.imap_sync import RESULT_FIELDS, FetchResult
from mordred_hermes.imports.store import ImportStore
from mordred_hermes.privacy_check import egress
from tests._fake_imap import FakeImapServer, FakeMailbox
from tests._mail_sync_helpers import CANARIES, Clock, FakeSecrets, gmail_creds, gmail_server, make_env, many

_LOCAL = SimpleNamespace(model="m", base_url="http://127.0.0.1:11434/v1")
_OPENAI = SimpleNamespace(model="gpt", base_url="https://api.openai.com/v1")


def _call(args: Any, agent: Any = _LOCAL, session: str | None = "s-1") -> dict[str, Any]:
    out = asyncio.run(mail_tool.mordred_mail_sync(args, parent_agent=agent, session_id=session))
    result: dict[str, Any] = json.loads(out)
    return result


def _hermes_model(home: Path, base_url: str) -> None:
    (home / "config.yaml").write_text(f"model:\n  default: m\n  base_url: {base_url}\n", encoding="utf-8")


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    db = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    db.initialize(tmp_path)
    return db


@pytest.fixture
def fetches(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    seen: list[int] = []

    def fake(max_messages: int, cancel: Any = None, lease: Any = None) -> dict[str, Any]:
        seen.append(max_messages)
        return dict(FetchResult(inserted=1).as_dict())

    monkeypatch.setattr(mail_tool, "_fetch", fake)
    return seen


# -- registration and schema ---------------------------------------------------------------------


def test_registered_beside_history_search_in_the_same_toolset() -> None:
    calls: list[dict[str, Any]] = []
    hermes_tools.register_tools(SimpleNamespace(register_tool=lambda **kw: calls.append(kw)))
    tool = next(c for c in calls if c["name"] == "mordred_mail_sync")
    assert tool["toolset"] == hermes_tools.TOOLSET
    assert tool["handler"] is mail_tool.mordred_mail_sync
    assert tool["check_fn"] is mail_tool.mail_sync_available and tool["is_async"] is True
    params = tool["schema"]["parameters"]
    assert set(params["properties"]) == {"max_messages"} and params["additionalProperties"] is False
    assert (params["properties"]["max_messages"]["minimum"], params["properties"]["max_messages"]["maximum"]) == (
        1,
        2000,
    )
    assert "counts only" in tool["description"]


def test_the_skill_says_when_to_call_it() -> None:
    text = hermes_tools.SKILL_PATH.read_text(encoding="utf-8")
    assert "mordred_mail_sync" in text and "sync my mail" in text


# -- check_fn ------------------------------------------------------------------------------------


@pytest.mark.parametrize("platform", ["darwin", "linux"])
@pytest.mark.parametrize(
    "base_url", ["http://127.0.0.1:11434/v1", "https://api.venice.ai/api/v1", "https://api.openai.com/v1"]
)
@pytest.mark.parametrize("gate", [True, False])
@pytest.mark.parametrize("configured", [True, False])
def test_check_fn_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, base_url: str, gate: bool, configured: bool
) -> None:
    _hermes_model(tmp_path, base_url)
    monkeypatch.setattr(mail_tool, "_platform", lambda: platform)
    monkeypatch.setattr(_gate, "check_protection", lambda _home: None if gate else _gate.refusal("not_armed"))
    monkeypatch.setattr(mail_tool, "_mail_configured", lambda: configured)
    expected = platform == "darwin" and "openai" not in base_url and gate and configured
    assert mail_tool.mail_sync_available() is expected


def test_configured_means_sealed_credentials_with_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "_platform", lambda: "darwin")
    assert mail_tool._mail_configured() is False
    folder = tmp_path / "mordred" / "mail"
    folder.mkdir(parents=True)
    (folder / "credentials.sealed").write_bytes(b"MMC1")
    (folder / "credentials.meta.json").write_text('{"account": "mail", "gmail": true, "roles": ["all"]}')
    assert mail_tool._mail_configured() is True
    monkeypatch.setattr(secrets, "_platform", lambda: "linux")
    assert mail_tool._mail_configured() is False


# -- arguments and the model gate ----------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        {"max_messages": 0},
        {"max_messages": 2001},
        {"max_messages": True},
        {"max_messages": 1.5},
        {"max_messages": "10"},
        {"max_messages": None},
        {"max_messages": 5, "mailbox": "INBOX"},
        {"account": "work"},
        ["max_messages"],
        "sync",
    ],
)
def test_invalid_arguments_are_refused_before_anything_runs(args: Any, fetches: list[int]) -> None:
    assert _call(args)["error"] == "invalid_request"
    assert fetches == []


@pytest.mark.parametrize(("args", "expected"), [({}, 2000), (None, 2000), ({"max_messages": 1}, 1)])
def test_valid_arguments(args: Any, expected: int, fetches: list[int]) -> None:
    result = _call(args)
    assert result["inserted"] == 1 and "note" in result
    assert fetches == [expected]


def test_a_model_that_may_not_see_private_data_is_refused_first(fetches: list[int]) -> None:
    assert _call({}, agent=_OPENAI)["error"] == "hermes_model_not_allowed"
    assert fetches == []


# -- end to end ----------------------------------------------------------------------------------


def _use_env(monkeypatch: pytest.MonkeyPatch, env: Any, options: list[Any] | None = None) -> None:
    real = imap_sync.run_fetch

    def run(opts: Any, _env: Any = None) -> FetchResult:
        if options is not None:
            options.append(opts)
        return real(opts, env)

    monkeypatch.setattr(imap_sync, "default_env", lambda: env)
    monkeypatch.setattr(imap_sync, "run_fetch", run)


def test_the_result_is_counts_only(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    server, audits, options = gmail_server(), [], []
    env = make_env(tmp_path, store, server, FakeSecrets(gmail_creds()), audits=audits)
    _use_env(monkeypatch, env, options)
    result = _call({"max_messages": 50})
    assert set(result) == RESULT_FIELDS | {"note"}
    assert (result["inserted"], result["error"], result["gmail"], result["partial"]) == (3, None, True, False)
    [opts] = options
    assert (opts.max_messages, opts.budget_s, opts.via, opts.dry_run) == (50, 60.0, "tool", False)
    text = json.dumps(result) + caplog.text + json.dumps(audits)
    assert [canary for canary in CANARIES if canary in text] == []
    assert audits[0]["via"] == "tool"


def test_the_time_budget_returns_partial_with_the_worker_finished(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(450))})
    clock = Clock()

    def slow(_uids: list[int]) -> None:
        clock.now += 61.0

    server.on_body_fetch = slow
    from tests._mail_sync_helpers import generic_creds

    env = make_env(tmp_path, store, server, FakeSecrets(generic_creds(sent=False)), clock=clock)
    _use_env(monkeypatch, env)
    result = _call({})
    assert (result["partial"], result["partial_reason"], result["inserted"]) == (True, "time_budget", 200)
    assert server.verbs[-1] == "LOGOUT"  # the session ended before the result was returned
    again = _call({})
    assert again["inserted"] == 200  # the next call continues from the committed cursor


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_a_concurrent_sync_is_sync_in_progress(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(tmp_path, store, gmail_server(), FakeSecrets(gmail_creds()))
    _use_env(monkeypatch, env)
    with imap_sync.fetch_lock(tmp_path):
        assert _call({})["error"] == "sync_in_progress"


def test_not_configured_is_a_code(tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch) -> None:
    env = make_env(tmp_path, store, gmail_server(), FakeSecrets(None))
    _use_env(monkeypatch, env)
    result = _call({})
    assert result["error"] == "mail_not_configured" and "mail setup" in result["note"]


def test_reader_sessions_can_sync_and_stay_untainted_by_it(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(tmp_path, store, gmail_server(), FakeSecrets(gmail_creds()))
    _use_env(monkeypatch, env)
    fresh = "mail-sync-fresh"
    assert _call({}, session=fresh)["inserted"] == 3
    assert not egress.is_tainted(fresh) and not egress.reader_mode_established(fresh)


# -- deadlines, cancellation and the worker thread -----------------------------------------------

_THREADS = ("mordred-mail-sync", "mordred-imap-watchdog")


def _fetch_threads() -> list[str]:
    return [thread.name for thread in threading.enumerate() if thread.name in _THREADS]


def _trickling(tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch, budget: float) -> FakeImapServer:
    from tests._mail_sync_helpers import generic_creds

    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=2, messages=many(3))})
    server.trickle_s = 0.01  # a byte every 10 ms: the socket never goes quiet long enough to time out
    env = make_env(tmp_path, store, server, FakeSecrets(generic_creds(sent=False)), clock=time.monotonic)
    _use_env(monkeypatch, env)
    monkeypatch.setattr(imap_sync, "TOOL_BUDGET_S", budget)
    return server


def test_a_trickling_server_returns_partial_and_no_thread_outlives_the_handler(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _trickling(tmp_path, store, monkeypatch, budget=0.5)
    started = time.monotonic()
    result = _call({})
    assert (result["partial"], result["partial_reason"], result["error"]) == (True, "time_budget", None)
    assert time.monotonic() - started < 5.0 and server.trickled > 5
    assert _fetch_threads() == []  # the worker and the session watchdog have ended
    assert server.closed.wait(5)


def test_a_cancelled_call_stops_the_fetch_and_joins_the_worker(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _trickling(tmp_path, store, monkeypatch, budget=60.0)

    async def scenario() -> float:
        task = asyncio.create_task(mail_tool.mordred_mail_sync({}, parent_agent=_LOCAL, session_id="s-1"))
        for _ in range(200):  # until the worker is inside the trickling body fetch
            await asyncio.sleep(0.02)
            if server.trickled:
                break
        assert server.trickled and "mordred-mail-sync" in _fetch_threads()
        started = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return time.monotonic() - started

    elapsed = asyncio.run(scenario())
    assert elapsed < 5.0
    assert _fetch_threads() == []  # joined before the cancellation finished
    assert server.closed.wait(5)
    assert rows_of(store) == 0


def rows_of(store: ImportStore) -> int:
    with store.connection() as conn:
        return int(conn.execute("SELECT count(*) FROM import_messages").fetchone()[0])


# -- bounded waits: a worker stuck where the session's bounds cannot reach -----------------------


def _stalled_resolver(monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    """``getaddrinfo`` never answers (until the returned event is set)."""
    from mordred_hermes.imports.mail import imap

    release = threading.Event()

    def never(_host: str, _port: int) -> list[Any]:
        release.wait(30)
        return []

    monkeypatch.setattr(imap, "_getaddrinfo", never)
    return release


def _resolver_threads() -> list[threading.Thread]:
    from mordred_hermes.imports.mail.imap import RESOLVER_NAME

    return [thread for thread in threading.enumerate() if thread.name == RESOLVER_NAME]


def test_a_cancellation_during_a_stalled_resolver_completes_at_once(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.extension.egress import EgressRoute
    from mordred_hermes.imports.mail import imap

    release = _stalled_resolver(monkeypatch)

    def connect(creds: Any, limits: Any) -> Any:
        direct = EgressRoute(None, None)
        return imap.connect(creds.imap_host, creds.imap_port, limits=limits, route_resolver=lambda _h: direct)

    env = make_env(tmp_path, store, gmail_server(), FakeSecrets(gmail_creds()), clock=time.monotonic, connect=connect)
    _use_env(monkeypatch, env)

    async def scenario() -> float:
        task = asyncio.create_task(mail_tool.mordred_mail_sync({}, parent_agent=_LOCAL, session_id="s-1"))
        for _ in range(200):  # until the worker waits for the resolver
            await asyncio.sleep(0.02)
            if _resolver_threads():
                break
        assert _resolver_threads() and "mordred-mail-sync" in _fetch_threads()
        started = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return time.monotonic() - started

    try:
        elapsed = asyncio.run(scenario())
        assert elapsed < 1.0  # the resolver wait answers the cancellation; nothing waits for the budget
        assert _fetch_threads() == []  # the worker and the watchdog have ended
        assert all(thread.daemon for thread in _resolver_threads())  # the stalled lookup is abandoned
        assert rows_of(store) == 0
    finally:
        release.set()
        for thread in _resolver_threads():
            thread.join(5)


@pytest.fixture
def stuck_fetch(monkeypatch: pytest.MonkeyPatch) -> Any:
    """``_fetch`` stuck somewhere that ignores the cancel token; short budget and graces."""
    release = threading.Event()
    tokens: list[Any] = []
    leases: list[Any] = []

    def stuck(_max_messages: int, cancel: Any = None, lease: Any = None) -> dict[str, Any]:
        tokens.append(cancel)
        leases.append(lease)
        release.wait(30)
        return dict(FetchResult(inserted=7).as_dict())

    monkeypatch.setattr(mail_tool, "_fetch", stuck)
    monkeypatch.setattr(imap_sync, "TOOL_BUDGET_S", 0.2)
    monkeypatch.setattr(mail_tool, "CANCEL_GRACE_S", 0.3)
    monkeypatch.setattr(mail_tool, "ABANDON_GRACE_S", 0.3)
    yield SimpleNamespace(release=release, tokens=tokens, leases=leases)
    release.set()
    for thread in _worker_threads():
        thread.join(5)  # the abandoned worker ends once released: nothing leaks into later tests


def _worker_threads() -> list[threading.Thread]:
    return [thread for thread in threading.enumerate() if thread.name == mail_tool.WORKER_NAME]


def test_repeated_cancellations_complete_within_the_bound_and_abandon_the_worker(stuck_fetch: Any) -> None:
    async def scenario() -> float:
        task = asyncio.create_task(mail_tool.mordred_mail_sync({}, parent_agent=_LOCAL, session_id="s-1"))
        await asyncio.sleep(0.05)
        started = time.monotonic()
        for _ in range(40):  # cancelled again and again: absorbed only until the bound
            task.cancel()
            await asyncio.sleep(0.02)
            if task.done():
                break
        with pytest.raises(asyncio.CancelledError):
            await task
        return time.monotonic() - started

    elapsed = asyncio.run(scenario())
    assert elapsed < 1.5  # remaining budget (0.15 s) + grace (0.3 s), not the worker's 30 s
    [token] = stuck_fetch.tokens
    assert token.cancelled
    assert all(thread.daemon for thread in _worker_threads()) and _worker_threads()  # abandoned, a daemon
    [lease] = stuck_fetch.leases
    assert lease.abandoned  # its writes are refused and its lock released before the cancellation completed


def test_a_worker_past_the_bound_is_abandoned_with_a_counts_only_result(stuck_fetch: Any) -> None:
    started = time.monotonic()
    result = _call({})
    assert time.monotonic() - started < 1.5
    assert set(result) == RESULT_FIELDS | {"note"}
    assert (result["partial"], result["partial_reason"], result["abandoned"]) == (True, "cancelled", True)
    assert (result["inserted"], result["error"]) == (0, None)
    [token] = stuck_fetch.tokens
    assert token.cancelled  # told to stop: it writes nothing more once it notices
    assert all(thread.daemon for thread in _worker_threads())
    [lease] = stuck_fetch.leases
    assert lease.abandoned


def test_a_normal_result_is_never_abandoned(fetches: list[int]) -> None:
    assert _call({})["abandoned"] is False


# -- an abandoned worker holds no lock and writes nothing later ------------------------------------


def _short_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(imap_sync, "TOOL_BUDGET_S", 0.2)
    monkeypatch.setattr(mail_tool, "CANCEL_GRACE_S", 0.3)
    monkeypatch.setattr(mail_tool, "ABANDON_GRACE_S", 0.3)


def _join_workers() -> None:
    for thread in _worker_threads():
        thread.join(10)
    assert _worker_threads() == []


def _runs(store: ImportStore) -> list[tuple[str, str]]:
    with store.connection() as conn:
        return [(str(a), str(b)) for a, b in conn.execute("SELECT state, counts_json FROM import_runs ORDER BY rowid")]


class _BlockingSecrets(FakeSecrets):
    """The first unseal blocks (a Touch ID prompt nobody answers) until released; later ones answer."""

    def __init__(self, creds: Any) -> None:
        super().__init__(creds)
        self.entered, self.release = threading.Event(), threading.Event()

    def load(self) -> Any:
        if self.loads == 0:
            self.loads += 1
            self.entered.set()
            self.release.wait(30)
            return self.creds
        return super().load()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_a_second_sync_right_after_an_abandonment_proceeds(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets_ = _BlockingSecrets(gmail_creds())
    env = make_env(tmp_path, store, gmail_server(), secrets_)
    _use_env(monkeypatch, env)
    _short_bounds(monkeypatch)
    try:
        first = _call({})
        assert (first["abandoned"], first["partial_reason"]) == (True, "cancelled")
        assert secrets_.entered.is_set() and _worker_threads()  # still blocked in the unseal, under the lock
        second = _call({})  # the lock was released by the handler: no sync_in_progress
        assert (second["error"], second["inserted"], second["abandoned"]) == (None, 3, False)
        cursors = store.meta_items("mail_imap.mail.")
    finally:
        secrets_.release.set()
        _join_workers()
    assert store.meta_items("mail_imap.mail.") == cursors  # the abandoned worker wrote nothing after waking
    assert rows_of(store) == 3 and [state for state, _counts in _runs(store)] == ["committed"]
    assert _call({})["error"] is None  # and no lock is left behind by it either


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock")
def test_an_abandoned_workers_late_batch_is_refused(
    tmp_path: Path, store: ImportStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.imports.store import ImportRefused

    env = make_env(tmp_path, store, gmail_server(), FakeSecrets(gmail_creds()))
    _use_env(monkeypatch, env)
    _short_bounds(monkeypatch)
    real = store.write_batch
    entered, release = threading.Event(), threading.Event()
    outcomes: list[str] = []

    def late(*args: Any, **kwargs: Any) -> Any:
        if not outcomes:
            entered.set()
            release.wait(30)  # the run is open; the handler gives up meanwhile
        try:
            written = real(*args, **kwargs)
        except ImportRefused as exc:
            outcomes.append(exc.code)
            raise
        outcomes.append("written")
        return written

    monkeypatch.setattr(store, "write_batch", late)
    try:
        result = _call({})
        assert entered.is_set() and result["abandoned"] is True
        assert _runs(store) == [("failed", '{"abandoned":1}')]  # failed BEFORE the handler returned
    finally:
        release.set()
        _join_workers()
    assert outcomes == ["run_not_open"]  # the late batch was refused inside its transaction
    assert rows_of(store) == 0 and store.meta_items("mail_imap.mail.") == {}
    again = _call({})
    assert (again["error"], again["inserted"]) == (None, 3) and outcomes[-1] == "written"
