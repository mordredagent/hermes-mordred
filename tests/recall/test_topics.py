"""Stored recall events and topics over a plain-SQLite import store (synthetic data, no SQLCipher)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.imports.records import (
    ConversationKind,
    ImportConversation,
    ImportMessage,
    OwnerClass,
    SenderKind,
    Source,
    local_conv_uid,
    local_source_uid,
)
from mordred_hermes.imports.store import ImportStore
from mordred_hermes.recall import topics
from mordred_hermes.recall.derive import selection_words
from mordred_hermes.recall.index import RecallIndex
from mordred_hermes.recall.service import RecallService
from tests.imports._factories import OWNER, SENT_AT, authored, message, part, participant, tg_conv

DAY = 86400
AGENT = participant("Assistant", "agent", OwnerClass.OTHER, SenderKind.BOT)
NOW = SENT_AT + 2 * DAY


def _conv(source: Source, key: str, title: str) -> ImportConversation:
    return ImportConversation(
        conv_uid=local_conv_uid(source, key),
        source=source,
        source_account="local",
        conversation_id=key,
        kind=ConversationKind.DIRECT,
        title=title,
        participants=(OWNER, AGENT),
        last_message_at=SENT_AT,
        message_count=0,
        archived=False,
        sync_cursor=None,
    )


def _chat(
    store: ImportStore, source: Source, key: str, title: str, turns: list[tuple[bool, str]], *, start: int
) -> None:
    """Commit one local conversation; its turns a minute apart."""
    conv = _conv(source, key, title)
    messages: list[ImportMessage] = []
    for i, (owner, text) in enumerate(turns):
        uid = local_source_uid(source, key, f"m{i:03d}")
        author = OWNER if owner else AGENT
        messages.append(
            message(
                uid,
                (part(uid, author=author, text=text),),
                conv_uid=conv.conv_uid,
                sender=author,
                sent_at=start + 60 * i,
            )
        )
    run = store.run_begin(source)
    result = store.write_thread(run, messages, conversation=conv)
    store.run_commit(run, {"inserted": result.inserted})


FPGA = [
    (True, "SmolVLM を FPGA に載せるための量子化を考えています"),
    (False, "FPGA の乗算器で SmolVLM を量子化すると精度が少し落ちます"),
    (True, "SmolVLM の蒸留で精度を戻せますか"),
    (False, "蒸留した SmolVLM は FPGA でも精度を保てます"),
]
GROK = [
    (True, "SmolVLM の量子化版で FPGA に入るものはありますか"),
    (False, "SmolVLM を量子化した FPGA 向けの版があります"),
]
GIF = [
    (True, "GIF のパレットを量子化してコマ数を減らしたい"),
    (False, "パレット量子化で GIF のコマを圧縮しました"),
    (True, "GIF のパレットはそのままでいいです"),
]


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    store = ImportStore(tmp_path / "mordred.db", sqlite3.connect)
    store.initialize(tmp_path)
    return store


def _search(store: ImportStore, text: str, **kwargs: Any) -> Any:
    topics.build(store)
    return topics.TopicIndex(store).events(text, **kwargs)


def test_chats_on_one_subject_share_an_event_and_another_subject_stays_apart(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    _chat(store, Source.GROK_BOT, "bot", "New Bot", GROK, start=SENT_AT + DAY)
    _chat(store, Source.CODEX, "gif", "GIF 作成", GIF, start=SENT_AT + DAY)

    result = _search(store, "量子化", now=NOW)

    assert result.hits == 6
    by_sources = {tuple(sorted(event.sources)): event for event in result.events}
    assert set(by_sources) == {("claude_code", "grok_bot"), ("codex",)}
    joint = by_sources["claude_code", "grok_bot"]
    assert joint.sources == {"claude_code": 1, "grok_bot": 1}
    assert {branch.source for branch in joint.branches} == {"claude_code", "grok_bot"}
    assert "SmolVLM" in joint.keywords
    assert joint.ongoing is True
    # The search reads the stored build: grouped under topics, best first.
    assert [len(card["events"]) for card in result.topics] == [1, 1]
    assert result.topics[0]["events"][0]["sources"] == {"claude_code": 1, "grok_bot": 1}


def test_a_chat_holds_two_events_that_one_topic_keeps_together(store: ImportStore) -> None:
    gif_later = [(owner, text) for owner, text in GIF]
    _chat(store, Source.CLAUDE_CODE, "long", "長い作業", [*FPGA, *gif_later], start=SENT_AT)
    # Move the GIF half four hours later: a pause that long always starts a new episode.
    with store.connection() as conn:
        conn.execute("UPDATE import_messages SET sent_at = sent_at + 4 * 3600 WHERE message_id >= 'm004'")
    topics.build(store)
    with store.connection() as conn:
        events = conn.execute("SELECT DISTINCT event_id FROM recall_episodes").fetchall()
        parents = conn.execute("SELECT DISTINCT parent_id FROM recall_groups WHERE level = 'event'").fetchall()
    assert len(events) == 2 and len(parents) == 1


def test_every_branch_anchors_on_a_hit_that_recall_open_can_show(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    [event] = _search(store, "蒸留", now=NOW).events
    [branch] = event.branches
    assert branch.hits == 2 and branch.title == "FPGA 推論エンジン"
    opened = RecallIndex(store).open(branch.anchor_part_uid, before=0, after=0)
    assert "蒸留" in opened[0]["text"] and "蒸留" in branch.excerpts[0]


def test_an_old_event_is_not_ongoing(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    [event] = _search(store, "蒸留", now=SENT_AT + 30 * DAY).events
    assert event.ongoing is False
    assert event.components["recency"] < 0.4


def test_a_resumed_session_that_replays_the_history_counts_as_one_chat(store: ImportStore) -> None:
    history = [(i % 2 == 0, f"SmolVLM の FPGA 量子化 その{i}") for i in range(12)]
    _chat(store, Source.CLAUDE_CODE, "first", "FPGA 推論エンジン", history, start=SENT_AT)
    _chat(store, Source.CLAUDE_CODE, "resumed", "FPGA 推論エンジン", [*history, (True, "続きです")], start=SENT_AT)
    [event] = _search(store, "量子化", now=NOW).events
    assert event.sources == {"claude_code": 1}


def test_telegram_never_enters_the_build(store: ImportStore) -> None:
    run = store.run_begin(Source.TELEGRAM)
    found = store.write_thread(run, [authored(1, OWNER, "SmolVLM の量子化の件です")], conversation=tg_conv())
    store.run_commit(run, {"inserted": found.inserted})
    assert _search(store, "量子化", now=NOW).events == []

    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    result = _search(store, "量子化", now=NOW)
    assert {source for event in result.events for source in event.sources} == {"claude_code"}
    with store.connection() as conn:
        stored = json.dumps(conn.execute("SELECT material FROM recall_episodes").fetchall(), ensure_ascii=False)
    assert "量子化の件" not in stored


def test_secret_shaped_text_never_reaches_the_stored_material(store: ImportStore) -> None:
    code = "MORT-ABCD-2345"
    token = "gAAAAABq" + "x" * 40
    turns = [(True, f"量子化の設定です {code} と {token} を使います"), (False, "量子化を設定しました")]
    _chat(store, Source.CLAUDE_CODE, "cfg", "設定", turns, start=SENT_AT)
    result = _search(store, "量子化", now=NOW)
    with store.connection() as conn:
        stored = conn.execute("SELECT material FROM recall_episodes UNION ALL SELECT material FROM recall_groups")
        dumped = json.dumps([stored.fetchall(), result.as_dict()], ensure_ascii=False)
        terms = {row[0] for row in conn.execute("SELECT term FROM recall_group_terms")}
    assert code not in dumped and "gAAAAABq" not in dumped
    assert not any("gaaaa" in term for term in terms)


def test_no_words_and_no_hits_give_no_events(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    assert _search(store, "   ", now=NOW).events == []
    assert _search(store, "存在しない語", now=NOW).events == []


def test_a_dismissed_conversation_is_left_out(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    hidden = {local_conv_uid(Source.CLAUDE_CODE, "fpga")}
    assert _search(store, "量子化", now=NOW, suppressed=hidden).events == []


def test_an_event_whose_hits_are_all_in_a_hidden_chat_is_left_out(store: ImportStore) -> None:
    # The FPGA chat and the Grok chat make one event; only the FPGA chat mentions 蒸留.
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    _chat(store, Source.GROK_BOT, "bot", "New Bot", GROK, start=SENT_AT + DAY)
    assert [sorted(event.sources) for event in _search(store, "蒸留", now=NOW).events] == [["claude_code", "grok_bot"]]

    hidden = {local_conv_uid(Source.CLAUDE_CODE, "fpga")}
    assert _search(store, "蒸留", now=NOW, suppressed=hidden).events == []
    # A word the other chat holds still finds the event, without the hidden chat.
    [event] = _search(store, "量子化", now=NOW, suppressed=hidden).events
    assert [branch.source for branch in event.branches] == ["grok_bot"]


class _Writer:
    def __init__(self, answers: dict[str, str | None] | None = None) -> None:
        self.asked: list[str] = []
        self.answers = answers or {}
        self.target = type("T", (), {"model": "fake"})()

    def lines(self, jobs: list[tuple[str, dict[str, Any]]]) -> list[str | None]:
        out = []
        for kind, _material in jobs:
            self.asked.append(kind)
            out.append(self.answers.get(kind, f"{kind} の一行"))
        return out

    def picks(self, jobs: list[tuple[list[dict[str, Any]], int]]) -> list[list[int] | None]:
        """By default every listed event shares the focus event's pursuit, so nothing is cut."""
        self.asked += ["pick"] * len(jobs)
        return [[i for i in range(len(items)) if i != focus] for items, focus in jobs]


class _Picky(_Writer):
    """Names as the same pursuit only the events whose top keyword is the focus event's."""

    def picks(self, jobs: list[tuple[list[dict[str, Any]], int]]) -> list[list[int] | None]:
        self.asked += ["pick"] * len(jobs)
        self.lists = [items for items, _focus in jobs]
        return [
            [i for i, item in enumerate(items) if i != focus and item["キーワード"][0] == items[focus]["キーワード"][0]]
            for items, focus in jobs
        ]


def test_lines_are_asked_once_per_item_and_kept_across_rebuilds(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    topics.build(store)
    writer = _Writer()
    written = topics.fill_lines(store, writer)
    counts = topics.line_counts(store)
    assert written == len(writer.asked) == counts["events"] + counts["topics"] + counts["episodes"]
    assert counts["events_with_lines"] == counts["events"]

    [event] = topics.TopicIndex(store).events("蒸留", now=NOW).events
    assert event.headline == "event の一行" and event.branches[0].summary == "episode の一行"
    assert event.topic is not None and event.topic["headline"] == "topic の一行"

    # An unchanged rebuild needs no new line; new material needs only its own.
    topics.build(store)
    assert topics.fill_lines(store, writer) == 0
    _chat(store, Source.GROK_BOT, "bot", "GIF の件", GIF, start=SENT_AT + 10 * DAY)
    topics.build(store)
    asked = len(writer.asked)
    topics.fill_lines(store, writer)
    assert len(writer.asked) - asked == 3  # the new chat's episode, event and topic only


def test_a_failed_line_is_not_stored_and_is_asked_again(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    topics.build(store)
    failing = _Writer({"event": None, "topic": None, "episode": None})
    assert topics.fill_lines(store, failing) == 0
    assert topics.line_counts(store)["events_with_lines"] == 0
    assert topics.fill_lines(store, _Writer()) > 0


def test_material_a_reachable_model_cannot_answer_is_set_aside(store: ImportStore) -> None:
    """So a few lines the model never manages do not keep its server busy every pass."""
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    topics.build(store)
    stubborn = _Writer({"event": None})
    failed: set[str] = set()
    written = topics.fill_lines(store, stubborn, failed=failed)
    assert written > 0 and len(failed) == stubborn.asked.count("event") == topics.line_counts(store)["events"]
    asked = len(stubborn.asked)
    assert topics.fill_lines(store, stubborn, skip=failed) == 0
    assert len(stubborn.asked) == asked  # nothing asked again

    # A model that could not be reached sets nothing aside: everything is asked again next pass.
    unreachable = _Writer({"event": None})
    unreachable.reachable = False  # type: ignore[attr-defined]
    missed: set[str] = set()
    topics.fill_lines(store, unreachable, failed=missed)
    assert missed == set()


def test_the_updater_rebuilds_only_when_the_committed_runs_change(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    updater = topics.TopicsUpdater(lambda: store, _Writer())
    updater.run_once()
    first = updater.last_build
    assert first is not None and topics.built_fingerprint(store) == topics.fingerprint(store)
    updater.run_once()
    assert updater.last_build is first
    _chat(store, Source.GROK_BOT, "bot", "New Bot", GROK, start=SENT_AT + DAY)
    updater.run_once()
    assert updater.last_build is not first and updater.last_build is not None
    assert topics.line_counts(store)["events_with_lines"] == topics.line_counts(store)["events"]


def test_average_linkage_merges_by_average_not_by_the_closest_pair() -> None:
    # 0-1 close, 2 close to 1 only: the average of (0,2) and (1,2) stays under the threshold.
    sims = {(0, 1): 0.9, (1, 2): 0.3}
    assert sorted(map(sorted, topics.average_linkage(3, sims, 0.2))) == [[0, 1], [2]]
    assert sorted(map(sorted, topics.average_linkage(3, sims, 0.1))) == [[0, 1, 2]]


def test_service_builds_on_first_use_and_returns_topics(tmp_path: Path, store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    service = RecallService(opener=lambda _home: store, home=tmp_path)
    assert topics.built_fingerprint(store) is None
    found = service.events("量子化")
    assert topics.built_fingerprint(store) is not None
    assert found["headlines"] == "stored" and found["topics"][0]["events"][0]["headline"] is None
    assert found["lines"]["events"] >= 1


def test_a_selection_is_looked_up_by_the_events_that_share_most_of_its_nouns(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    _chat(store, Source.CODEX, "gif", "GIF 作成", GIF, start=SENT_AT + DAY)
    topics.build(store)
    index = topics.TopicIndex(store)

    found = index.selection_events(["SmolVLM", "FPGA", "蒸留", "量子化", "ヤマネコ"], now=NOW)

    # 量子化 is in both chats, but the GIF chat holds too little of the selection to show.
    assert [event.sources for event in found.events] == [{"claude_code": 1}]
    # The nouns shared, the rarest first; ヤマネコ is in no chat and 量子化 in both.
    assert found.query.split()[-1] == "量子化" and "ヤマネコ" not in found.query.split()
    assert found.hits > 0 and found.events[0].branches[0].hits > 0


def test_a_selection_about_something_never_discussed_finds_nothing(store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    _chat(store, Source.CODEX, "gif", "GIF 作成", GIF, start=SENT_AT + DAY)
    topics.build(store)

    # One common noun (量子化) among many the store never saw is not enough.
    found = topics.TopicIndex(store).selection_events(["ヤマネコ", "冬毛", "北海道", "観察記録", "量子化"], now=NOW)

    assert found.events == [] and found.topics == [] and found.query == "" and found.hits == 0


def test_a_long_selection_finds_events_by_its_keywords(tmp_path: Path, store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    _chat(store, Source.CODEX, "gif", "GIF 作成", GIF, start=SENT_AT + DAY)
    service = RecallService(opener=lambda _home: store, home=tmp_path)
    selection = "このページでは SmolVLM を FPGA の乗算器に合わせて量子化する手順を、精度の比較と一緒に説明しています。"

    as_typed = service.events(selection)
    found = service.events(selection, selection=True)

    assert as_typed["hits"] == 0
    assert found["hits"] > 0
    assert set(found["query"].split()) <= set(selection_words(selection))
    assert {source for event in found["events"] for source in event["sources"]} == {"claude_code"}
    assert found["derived"]["keywords"]


def test_a_long_selection_about_something_else_finds_nothing(tmp_path: Path, store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    service = RecallService(opener=lambda _home: store, home=tmp_path)
    selection = "ヤマネコの冬毛と夏毛の違いについて、北海道の観察記録をもとにまとめた文章です。"

    found = service.events(selection, selection=True)

    assert found["events"] == [] and found["topics"] == [] and found["query"] == ""


def test_a_short_selection_is_searched_as_the_search_box_would(tmp_path: Path, store: ImportStore) -> None:
    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    _chat(store, Source.CODEX, "gif", "GIF 作成", GIF, start=SENT_AT + DAY)
    service = RecallService(opener=lambda _home: store, home=tmp_path)

    typed = service.events("量子化")
    selected = service.events("量子化", selection=True)

    assert selected["query"] == "量子化"
    assert selected["hits"] == typed["hits"]
    assert selected["derived"]["keywords"] == ["量子化"]
    assert "derived" not in typed


def _grab_bag(store: ImportStore) -> None:
    """One general-assistant chat: the FPGA work, then four hours later an unrelated GIF question."""
    _chat(store, Source.GROK_BOT, "bot", "New Bot", [*FPGA, *GIF], start=SENT_AT)
    with store.connection() as conn:
        conn.execute("UPDATE import_messages SET sent_at = sent_at + 4 * 3600 WHERE message_id >= 'm004'")


def _topic_count(store: ImportStore) -> int:
    with store.connection() as conn:
        return int(conn.execute("SELECT count(*) FROM recall_groups WHERE level = 'topic'").fetchone()[0])


def test_a_chat_about_anything_is_cut_where_its_events_do_not_share_a_pursuit(store: ImportStore) -> None:
    _grab_bag(store)
    # Without the model's answers the same-chat floor keeps both events in one topic.
    first = topics.build(store)
    assert _topic_count(store) == 1 and first.waiting == 1 and first.pick_jobs == []

    writer = _Picky()
    updater = topics.TopicsUpdater(lambda: store, writer)
    updater.run_once()
    assert _topic_count(store) == 2
    assert topics.line_counts(store)["picks_pending"] == 0
    # The list shows each event's headline, keywords and one user message.
    assert {"見出し", "キーワード", "本人の発言"} == set(writer.lists[0][0])
    assert writer.lists[0][0]["見出し"] == "event の一行"

    [event] = topics.TopicIndex(store).events("蒸留", now=NOW).events
    assert event.topic is not None and event.topic["events"] == 1
    # The branch says its chat runs through two topics.
    assert event.branches[0].chat_topics == 2
    assert event.branches[0].as_dict()["chat_topics"] == 2


def test_events_that_name_each_other_stay_in_one_topic_and_answers_are_kept(store: ImportStore) -> None:
    _grab_bag(store)
    writer = _Writer()
    updater = topics.TopicsUpdater(lambda: store, writer)
    updater.run_once()
    assert _topic_count(store) == 1 and writer.asked.count("pick") == 2
    [event] = topics.TopicIndex(store).events("蒸留", now=NOW).events
    assert event.branches[0].chat_topics == 1

    # A rebuild reads the stored answers: no question is asked again.
    rebuilt = topics.build(store)
    assert rebuilt.pick_jobs == [] and rebuilt.waiting == 0
    topics.TopicsUpdater(lambda: store, writer).run_once()
    assert writer.asked.count("pick") == 2


def test_a_one_sided_answer_does_not_link_two_events(store: ImportStore) -> None:
    _grab_bag(store)

    class _OneSided(_Writer):
        def picks(self, jobs: list[tuple[list[dict[str, Any]], int]]) -> list[list[int] | None]:
            self.asked += ["pick"] * len(jobs)
            return [[1] if focus == 0 else [] for _items, focus in jobs]

    topics.TopicsUpdater(lambda: store, _OneSided()).run_once()
    assert _topic_count(store) == 2


def test_a_failed_answer_keeps_the_topic_whole_and_is_asked_again(store: ImportStore) -> None:
    _grab_bag(store)

    class _Failing(_Writer):
        def picks(self, jobs: list[tuple[list[dict[str, Any]], int]]) -> list[list[int] | None]:
            self.asked += ["pick"] * len(jobs)
            return [None for _ in jobs]

    topics.TopicsUpdater(lambda: store, _Failing()).run_once()
    assert _topic_count(store) == 1 and topics.line_counts(store)["picks_pending"] == 2
    # A fresh updater (a restart) finds the questions again through a rebuild.
    picky = _Picky()
    topics.TopicsUpdater(lambda: store, picky).run_once()
    assert _topic_count(store) == 2 and picky.asked.count("pick") == 2


def test_a_topic_is_described_by_one_message_from_each_episode() -> None:
    def ep(texts: list[str]) -> Any:
        return type("E", (), {"parts": [type("P", (), {"owner": True, "text": t})() for t in texts]})()

    big = ep([f"ペストの件について質問その{i}です" for i in range(5)])
    small = ep(["量子化の件について質問しました"])
    expected = ["ペストの件について質問その0です", "量子化の件について質問しました"]
    assert topics._spread_messages([big, small]) == expected


def test_a_branch_names_the_folder_its_session_worked_in(store: ImportStore) -> None:
    from mordred_hermes.imports.local._model import place_key

    _chat(store, Source.CLAUDE_CODE, "fpga", "FPGA 推論エンジン", FPGA, start=SENT_AT)
    topics.build(store)
    found = topics.TopicIndex(store).events("FPGA", limit=3, suppressed=set())
    branch = found.events[0].branches[0]
    assert branch.folder is None
    store.set_meta(place_key(branch.source, branch.conv_uid), "/repos/fpga")
    found = topics.TopicIndex(store).events("FPGA", limit=3, suppressed=set())
    assert found.events[0].branches[0].folder == "/repos/fpga"
    assert found.events[0].as_dict()["branches"][0]["folder"] == "/repos/fpga"
