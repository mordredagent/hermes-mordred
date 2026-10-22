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

    def fake(max_messages: int, cancel: Any = None) -> dict[str, Any]:
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
