"""Antigravity conversations: the summaries database's text copy, cut at its step offsets, with step times."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from mordred_hermes.imports.local import antigravity, run_local_import
from mordred_hermes.imports.records import Source
from mordred_hermes.imports.store import ImportStore

CONV = "3bfc6a4e-f4b4-4d0e-8cdc-397a039b78e2"
T0 = 1_795_377_707


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _metadata(seconds: int) -> bytes:
    """``metadata`` with field 1 = Timestamp{seconds}, plus an unrelated field."""
    stamp = b"\x08" + _varint(seconds)
    return b"\x0a" + _varint(len(stamp)) + stamp + b"\x30" + _varint(T0 + 999)


def _layout(root: Path, *, user: list[tuple[int, str]], agent: list[tuple[int, str]], title: str = "") -> None:
    """A minimal Antigravity folder: one conversation database and the summaries database."""
    (root / "conversations").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / "conversations" / f"{CONV}.db")
    con.execute("create table steps (idx integer primary key, step_type integer, metadata blob, step_payload blob)")
    for step in range(max(s for s, _ in user + agent) + 1):
        con.execute("insert into steps values (?, 0, ?, x'00')", (step, _metadata(T0 + step * 10)))
    con.commit()
    con.close()

    def body(turns: list[tuple[int, str]]) -> tuple[str, str]:
        text, offsets = b"", []
        for step, words in turns:
            offsets.append([step, len(text)])
            text += words.encode() + b"\n"
        return text.decode(), json.dumps(offsets, separators=(",", ":"))

    user_body, user_offsets = body(user)
    agent_body, agent_offsets = body(agent)
    con = sqlite3.connect(root / antigravity.SUMMARIES)
    con.execute(
        "create table conversation_summaries (conversation_id text primary key, title text, workspace_uris text)"
    )
    con.execute("insert into conversation_summaries values (?, ?, ?)", (CONV, title, "file:///Users/me/repos/demo"))
    con.execute(
        "create table conversations_fts (conversation_id, chunk_index, user_step_byte_offsets,"
        " agent_step_byte_offsets, user_body, agent_body)"
    )
    con.execute("insert into conversations_fts values (?, -1, '', '', '', '')", (CONV,))
    con.execute(
        "insert into conversations_fts values (?, 0, ?, ?, ?, ?)",
        (CONV, user_offsets.encode(), agent_offsets.encode(), user_body, agent_body),
    )
    con.commit()
    con.close()


def test_a_conversation_is_read_in_step_order_with_times(tmp_path: Path) -> None:
    _layout(
        tmp_path,
        user=[(0, "インドの電気代を比べて"), (6, "スイスも足して")],
        agent=[(1, ""), (3, ""), (5, "| 構成 | 円 |\n|---|---|\n| B200 | 42 |"), (7, "スイスは CHF 0.27 です。")],
        title="電気代の比較",
    )
    [transcript] = antigravity.read(tmp_path / "conversations" / f"{CONV}.db")
    assert transcript.key == CONV and transcript.title == "電気代の比較"
    assert transcript.place == "/Users/me/repos/demo"
    assert [(e.key, e.role, e.sent_at) for e in transcript.entries] == [
        ("s0", "owner", T0),
        ("s5", "agent", T0 + 50),
        ("s6", "owner", T0 + 60),
        ("s7", "agent", T0 + 70),
    ]
    assert transcript.entries[1].text == "| 構成 | 円 |\n|---|---|\n| B200 | 42 |"


def test_without_the_summaries_database_nothing_is_read(tmp_path: Path) -> None:
    _layout(tmp_path, user=[(0, "a")], agent=[(1, "b")])
    (tmp_path / antigravity.SUMMARIES).unlink()
    assert antigravity.read(tmp_path / "conversations" / f"{CONV}.db") == []


@pytest.mark.parametrize("blob", [None, b"", b"\xff\xff\xff", b"\x0a\x02\x08\x05"])
def test_a_missing_or_odd_step_time_is_none(blob: bytes | None) -> None:
    assert antigravity.step_time(blob) is None


def test_import_writes_once_and_finds_duplicates_after(tmp_path: Path) -> None:
    root = tmp_path / "antigravity"
    _layout(root, user=[(0, "質問")], agent=[(1, "答え")])
    store = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    store.initialize(tmp_path)

    first = run_local_import(Source.ANTIGRAVITY, home=tmp_path, root=root, opener=lambda _h: store).as_dict()
    assert first["conversations"] == 1 and first["inserted"] == 2
    again = run_local_import(Source.ANTIGRAVITY, home=tmp_path, root=root, opener=lambda _h: store).as_dict()
    assert again["files_changed"] == 0  # nothing changed: not read again

    # The text lives in the summaries database: a change there is a change of every conversation.
    con = sqlite3.connect(root / antigravity.SUMMARIES)
    con.execute("update conversation_summaries set title = 'renamed'")
    con.commit()
    con.close()
    third = run_local_import(Source.ANTIGRAVITY, home=tmp_path, root=root, opener=lambda _h: store).as_dict()
    assert third["files_changed"] == 1 and third["inserted"] == 0 and third["duplicates"] == 2
