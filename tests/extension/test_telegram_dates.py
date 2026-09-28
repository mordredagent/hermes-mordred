"""Date-bounded questions, empty-answer handling, and the saved sync scope."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.extension.egress import EgressRoute
from mordred_hermes.extension.telegram import ask, hermes_tools, secrets, service, store, tee
from mordred_hermes.wizard import telegram_cli


def _ts(day: str, hour: int = 12) -> int:
    return int(dt.datetime.strptime(f"{day} {hour}", "%Y-%m-%d %H").astimezone().timestamp())


def _archive(tmp_path) -> tuple[store.ArchiveStore, store.ArchiveIndex]:
    archive = store.ArchiveStore(b"\x03" * 32, tmp_path)
    archive.append_messages(
        1,
        [
            store.StoredMessage(id=1, date=_ts("2026-09-01"), sender="A", text="old unrelated"),
            store.StoredMessage(id=2, date=_ts("2026-09-09"), sender="A", text="hello there"),
            store.StoredMessage(id=3, date=_ts("2026-09-15", 23), sender="B", text="late on the 15th"),
            store.StoredMessage(id=4, date=_ts("2026-09-16", 1), sender="B", text="after the range"),
        ],
    )
    index = store.ArchiveIndex(
        last_sync=_ts("2026-09-16", 2),
        dialogs={1: store.DialogInfo(1, "group", "G", last_date=_ts("2026-09-16", 1), message_count=4)},
    )
    return archive, index


def test_local_day_bounds_are_inclusive_local_days():
    since, until = ask.local_day_bounds("2026-09-08", "2026-09-15")
    assert since == _ts("2026-09-08", 0) and until == _ts("2026-09-16", 0)
    with pytest.raises(ask.AskError, match="invalid_date"):
        ask.local_day_bounds("2026-09-15", "2026-09-01")
    with pytest.raises(ask.AskError, match="invalid_date"):
        ask.local_day_bounds("15/09/2026", None)


def test_period_questions_use_every_message_in_the_period_regardless_of_words(tmp_path):
    archive, index = _archive(tmp_path)
    since, until = ask.local_day_bounds("2026-09-08", "2026-09-15")
    request = ask.AskRequest(question="どんなメッセージが来てますか", since=since, until=until)
    sel = ask.select_context(archive, index, request, ask.Aliases(enabled=False), budget_tokens=10_000)
    texts = "\n".join(sel.lines)
    assert "hello there" in texts and "late on the 15th" in texts
    assert "old unrelated" not in texts and "after the range" not in texts


def test_prompt_states_today_coverage_and_period(tmp_path):
    archive, index = _archive(tmp_path)
    since, until = ask.local_day_bounds("2026-09-08", "2026-09-15")
    request = ask.AskRequest(question="q", since=since, until=until)
    sel = ask.select_context(archive, index, request, ask.Aliases(), budget_tokens=10_000)
    now = dt.datetime(2026, 9, 28, 10, tzinfo=dt.UTC)
    user = ask.build_messages("q", sel, request=request, last_sync=index.last_sync, now=now)[1]["content"]
    assert user.startswith("Today: 2026-09-28")
    assert "last updated 2026-09-16" in user
    assert "ALL imported messages from 2026-09-08 00:00 to 2026-09-16 00:00" in user


def test_dates_in_prompt_are_local_time(tmp_path):
    ts = _ts("2026-09-15", 23)
    assert ask._iso(ts) == "2026-09-15 23:00"


class _Resp:
    def __init__(self, chunks: list[bytes]):
        self.status = 200
        self._chunks = chunks

        class _C:
            async def iter_any(inner) -> Any:
                for c in self._chunks:
                    yield c

        self.content = _C()

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_e: object) -> None:
        return None


class _Session:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.bodies: list[dict[str, Any]] = []

    def post(self, url: str, **kw: Any) -> _Resp:
        self.bodies.append(kw["json"])
        return _Resp(self.chunks)

    def get(self, url: str, **kw: Any) -> Any:
        raise AssertionError

    async def close(self) -> None:
        return None


def _local_service(tmp_path, chunks: list[bytes]) -> tuple[service.TelegramService, _Session]:
    archive, index = _archive(tmp_path / "tg")
    archive.save_index(index)
    value = secrets.TelegramSecrets(
        api_id=1,
        api_hash="ab" * 16,
        store_key=b"\x03" * 32,
        session="s",
        backend="local",
        local_endpoint="http://127.0.0.1:1/v1",
        local_model="m",
    )
    session = _Session(chunks)
    svc = service.TelegramService(
        secret_store=SimpleNamespace(load=lambda fresh=True: value, flags=lambda: {}),
        archive_root=tmp_path / "tg",
        http_session_factory=lambda _r, _t: session,
        route_resolver=lambda _h: EgressRoute(None, None),
        policy_check=lambda _b, _u: None,
    )
    return svc, session


def _delta(text: str) -> bytes:
    return ("data: " + json.dumps({"choices": [{"delta": {"content": text}}]}) + "\n").encode()


def test_empty_answer_is_an_error_not_silence(tmp_path):
    svc, _ = _local_service(tmp_path, [b"data: [DONE]\n"])

    async def run() -> str:
        return "".join([c async for c in svc.ask(ask.AskRequest(question="hello"), lambda _m: None)])

    with pytest.raises(ask.AskError, match="llm_empty_answer"):
        asyncio.run(run())


def test_thinking_blocks_are_removed_across_chunks(tmp_path):
    svc, session = _local_service(
        tmp_path, [_delta("<thi"), _delta("nk>plan..."), _delta("</think>Answer"), _delta(".")]
    )

    async def run() -> str:
        return "".join([c async for c in svc.ask(ask.AskRequest(question="hello"), lambda _m: None)])

    assert asyncio.run(run()) == "Answer."
    assert session.bodies[0]["max_tokens"] == ask.ANSWER_TOKENS


def test_hermes_tool_passes_dates_and_reports_coverage(monkeypatch):
    seen: list[Any] = []

    class _Svc:
        async def ask(self, request: Any, on_meta: Any) -> Any:
            seen.append(request)
            yield "ok"

    monkeypatch.setattr(hermes_tools, "_service", lambda: _Svc())
    monkeypatch.setattr(hermes_tools, "_coverage", lambda: {"archive_updated": "x", "sync_running": False, "hint": ""})
    agent = SimpleNamespace(model="m", base_url="http://127.0.0.1:1/v1")
    out = json.loads(
        asyncio.run(
            hermes_tools.telegram_ask(
                {"question": "q", "start_date": "2026-09-08", "end_date": "2026-09-15"}, parent_agent=agent
            )
        )
    )
    assert out["answer"] == "ok" and out["coverage"]["sync_running"] is False
    assert (seen[0].since, seen[0].until) == ask.local_day_bounds("2026-09-08", "2026-09-15")
    bad = json.loads(asyncio.run(hermes_tools.telegram_ask({"question": "q", "start_date": "9/8"}, parent_agent=agent)))
    assert bad == {"error": "invalid_date"}


def test_archive_busy_reflects_the_sync_lock(tmp_path):
    archive = store.ArchiveStore(b"\x03" * 32, tmp_path)
    assert store.archive_busy(tmp_path) is False
    with archive.locked():
        assert store.archive_busy(tmp_path) is True
    assert store.archive_busy(tmp_path) is False


def test_sync_scope_is_saved_and_used(tmp_path):
    vault = tee.TeeSecretStore(tmp_path / "tg", backend_factory=lambda: None, audit_sink=lambda _e: None)
    assert vault.sync_scope() == {}
    vault.save_sync_scope({"include_channels": False, "include_archived": False, "limit_per_dialog": 500})
    svc = service.TelegramService(secret_store=vault, archive_root=tmp_path / "tg")
    opts = svc.sync_options()
    assert (opts.include_channels, opts.include_archived, opts.limit_per_dialog) == (False, False, 500)
    opts = svc.sync_options({"include_channels": True, "limit_per_dialog": None})
    assert (opts.include_channels, opts.include_archived, opts.limit_per_dialog) == (True, False, 500)


def test_cli_sync_uses_saved_scope_unless_all(monkeypatch):
    used: list[Any] = []

    class _Svc:
        def sync_options(self, overrides: Any) -> Any:
            return service.TelegramService.sync_options(
                SimpleNamespace(
                    _secrets=SimpleNamespace(
                        sync_scope=lambda: {
                            "include_channels": False,
                            "include_archived": False,
                            "limit_per_dialog": 500,
                        }
                    )
                ),
                overrides,
            )

    async def fake_run(_svc: Any, options: Any) -> int:
        used.append(options)
        return 0

    monkeypatch.setattr(telegram_cli, "_run_sync", fake_run)
    assert telegram_cli.telegram_sync(service=_Svc()) == 0
    assert (used[-1].include_channels, used[-1].limit_per_dialog) == (False, 500)
    assert telegram_cli.telegram_sync(service=_Svc(), everything=True) == 0
    assert (used[-1].include_channels, used[-1].include_archived, used[-1].limit_per_dialog) == (True, True, None)
