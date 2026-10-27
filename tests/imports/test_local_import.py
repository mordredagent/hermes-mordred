"""Local transcript import (Codex, Claude Code, Grok Bot) over a plain-SQLite store (synthetic data)."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from pathlib import Path

import pytest

from mordred_hermes.imports.local import LocalImportError, claude_code, codex, grok_bot, run_local_import
from mordred_hermes.imports.local.runner import local_status
from mordred_hermes.imports.records import Source, local_conv_uid, local_source_uid, source_of
from mordred_hermes.imports.store import ImportStore
from mordred_hermes.recall.index import RecallIndex


def _jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    return path


def _codex_rows() -> list[dict[str, object]]:
    def msg(role: str, text: str, at: str) -> dict[str, object]:
        kind = "input_text" if role == "user" else "output_text"
        return {
            "timestamp": at,
            "type": "response_item",
            "payload": {"type": "message", "role": role, "content": [{"type": kind, "text": text}]},
        }

    return [
        {"timestamp": "2026-10-01T09:00:00Z", "type": "session_meta", "payload": {"id": "sess-1"}},
        msg("user", "<environment_context>cwd</environment_context>", "2026-10-01T09:00:01Z"),
        msg("user", "経費精算の締め切りを調べて", "2026-10-01T09:00:02Z"),
        {"type": "response_item", "payload": {"type": "reasoning", "summary": []}},
        {"type": "response_item", "payload": {"type": "function_call", "name": "shell"}},
        msg("assistant", "\x1b[1m締め切りは毎月25日\x1b[0mです。", "2026-10-01T09:00:03Z"),
    ]


def _claude_rows() -> list[dict[str, object]]:
    return [
        {"type": "custom-title", "customTitle": "請求書の確認"},
        {
            "type": "user",
            "uuid": "u-1",
            "sessionId": "cc-1",
            "timestamp": "2026-10-02T10:00:00Z",
            "message": {"role": "user", "content": "源泉税の書類はどこ?"},
        },
        {
            "type": "user",
            "uuid": "u-meta",
            "sessionId": "cc-1",
            "isMeta": True,
            "message": {"content": "caveat"},
        },
        {
            "type": "assistant",
            "uuid": "a-1",
            "sessionId": "cc-1",
            "timestamp": "2026-10-02T10:00:05Z",
            "message": {
                "content": [
                    {"type": "thinking", "thinking": "hidden"},
                    {"type": "tool_use", "name": "Read"},
                    {"type": "text", "text": "しめきりは来週です。"},
                ]
            },
        },
        {
            "type": "user",
            "uuid": "u-2",
            "sessionId": "cc-1",
            "message": {"content": [{"type": "tool_result", "content": "file body"}]},
        },
        {"type": "assistant", "uuid": "side", "sessionId": "cc-1", "isSidechain": True, "message": {"content": "x"}},
    ]


def _blob_name(key: str) -> str:
    return base64.b32encode(key.encode()).decode().rstrip("=").lower() + ".blob"


def _grok_root(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    prefix = "sand.client.slice.account.acct"
    roster = {"schemaVersion": 1, "value": {"rows": [{"id": "bot-1", "name": "Research"}]}}
    replica = {
        "schemaVersion": 1,
        "value": {
            "entries": [
                {
                    "kind": "message",
                    "id": "e1",
                    "role": "user",
                    "content": "Codex の差分は?",
                    "timestampMs": 1_790_000_000_000,
                },
                {
                    "kind": "send-message",
                    "id": "e2",
                    "message": {"type": "text", "content": "リマインダーを設定しました"},
                },
                {"kind": "send-message", "id": "e3", "message": {"type": "widget", "widget": {}}},
                {"kind": "voice-call", "id": "e4", "call": {}},
            ]
        },
    }
    (root / _blob_name(f"{prefix}.roster.last-roster")).write_text(json.dumps(roster), encoding="utf-8")
    (root / _blob_name(f"{prefix}.transcript.replicas.bot-1")).write_text(json.dumps(replica), encoding="utf-8")
    (root / _blob_name(f"{prefix}.sidebar.last-sections")).write_text("{}", encoding="utf-8")
    return root


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    store = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    store.initialize(tmp_path)
    return store


def _run(source: Source, store: ImportStore, home: Path, root: Path) -> dict[str, object]:
    return run_local_import(source, home=home, root=root, opener=lambda _home: store).as_dict()


def test_local_uids_round_trip() -> None:
    uid = local_source_uid(Source.CLAUDE_CODE, "cc-1", "u-1")
    assert uid == "claude:cc-1:u-1"
    assert source_of(uid) is Source.CLAUDE_CODE
    assert local_conv_uid(Source.GROK_BOT, "bot-1") == "grok:bot-1"
    assert source_of("codex:sess:000001") is Source.CODEX


def test_codex_keeps_only_the_turns(tmp_path: Path) -> None:
    [transcript] = codex.read(_jsonl(tmp_path / "2026/10/01/rollout-a.jsonl", _codex_rows()))
    assert transcript.key == "sess-1"
    assert [(e.role, e.text) for e in transcript.entries] == [
        ("owner", "経費精算の締め切りを調べて"),
        ("agent", "締め切りは毎月25日です。"),
    ]
    assert [e.key for e in transcript.entries] == ["000001", "000002"]


def test_claude_code_skips_meta_tools_and_sidechains(tmp_path: Path) -> None:
    [transcript] = claude_code.read(_jsonl(tmp_path / "proj/cc-1.jsonl", _claude_rows()))
    assert transcript.title == "請求書の確認"
    assert [(e.key, e.text) for e in transcript.entries] == [
        ("u-1", "源泉税の書類はどこ?"),
        ("a-1", "しめきりは来週です。"),
    ]


def test_grok_bot_reads_replicas_with_bot_names(tmp_path: Path) -> None:
    root = _grok_root(tmp_path / "grok")
    [path] = list(grok_bot.files(root))
    [transcript] = grok_bot.read(path, grok_bot.bot_names(root))
    assert (transcript.key, transcript.title, transcript.agent_name) == ("bot-1", "Research", "Research")
    assert [(e.role, e.text) for e in transcript.entries] == [
        ("owner", "Codex の差分は?"),
        ("agent", "リマインダーを設定しました"),
    ]


def test_import_is_idempotent_and_skips_unchanged_files(tmp_path: Path, store: ImportStore) -> None:
    root = tmp_path / "codex"
    path = _jsonl(root / "2026/10/01/rollout-a.jsonl", _codex_rows())
    first = _run(Source.CODEX, store, tmp_path, root)
    assert (first["files_changed"], first["inserted"], first["duplicates"]) == (1, 2, 0)
    again = _run(Source.CODEX, store, tmp_path, root)
    assert (again["files_seen"], again["files_changed"], again["inserted"]) == (1, 0, 0)
    # A touched file is read again, but its messages are duplicates: nothing is written twice.
    os.utime(path, ns=(1, 1))
    touched = _run(Source.CODEX, store, tmp_path, root)
    assert (touched["files_changed"], touched["inserted"], touched["duplicates"]) == (1, 0, 2)
    assert store.status()["sources"]["codex"]["messages"] == 2


def test_appended_turns_are_the_only_inserts(tmp_path: Path, store: ImportStore) -> None:
    root = tmp_path / "claude"
    path = _jsonl(root / "proj/cc-1.jsonl", _claude_rows())
    _run(Source.CLAUDE_CODE, store, tmp_path, root)
    rows = [
        *_claude_rows(),
        {"type": "user", "uuid": "u-3", "sessionId": "cc-1", "message": {"content": "ありがとう"}},
    ]
    _jsonl(path, rows)
    os.utime(path, ns=(2, 2))
    result = _run(Source.CLAUDE_CODE, store, tmp_path, root)
    assert (result["inserted"], result["duplicates"]) == (1, 2)


def test_every_source_is_searchable(tmp_path: Path, store: ImportStore) -> None:
    _run(Source.CODEX, store, tmp_path, _jsonl(tmp_path / "codex/rollout-a.jsonl", _codex_rows()).parent)
    _run(Source.CLAUDE_CODE, store, tmp_path, _jsonl(tmp_path / "claude/p/cc-1.jsonl", _claude_rows()).parent.parent)
    _run(Source.GROK_BOT, store, tmp_path, _grok_root(tmp_path / "grok"))
    index = RecallIndex(store)
    assert {c.source for c in index.search("締め切り").cards} == {"codex"}
    assert {c.source for c in index.search("源泉税").cards} == {"claude_code"}
    assert {c.source for c in index.search("リマインダー").cards} == {"grok_bot"}


def test_refusals_are_codes(tmp_path: Path, store: ImportStore) -> None:
    with pytest.raises(LocalImportError) as missing:
        _run(Source.CODEX, store, tmp_path, tmp_path / "absent")
    assert missing.value.code == "source_not_found"
    with pytest.raises(LocalImportError) as unknown:
        run_local_import("telegram", home=tmp_path, root=tmp_path)
    assert unknown.value.code == "unknown_source"


def test_second_writer_is_refused(tmp_path: Path, store: ImportStore) -> None:
    root = _jsonl(tmp_path / "codex/rollout-a.jsonl", _codex_rows()).parent
    from mordred_hermes.imports.local.runner import _writer_lock

    with _writer_lock(tmp_path, Source.CODEX), pytest.raises(LocalImportError) as busy:
        _run(Source.CODEX, store, tmp_path, root)
    assert busy.value.code == "import_running"


def test_local_status_reports_folders_only(tmp_path: Path) -> None:
    (tmp_path / ".codex" / "sessions").mkdir(parents=True)
    status = local_status(tmp_path)
    assert status == {
        "codex": {"available": True},
        "claude_code": {"available": False},
        "grok_bot": {"available": False},
    }
