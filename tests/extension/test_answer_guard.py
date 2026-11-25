"""The extension chat's Python checks: plan the turn, review the answer, correct it."""

# ruff: noqa: RUF001 - messages as users type them, with full-width punctuation

from __future__ import annotations

import pytest

from mordred_hermes.extension import answer_guard as guard

LOOKUP_TOOLS = ("mordred_memory_search", "mordred_history_search")


# ---- planning ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("question", "action"),
    [
        ("ls コマンドを実行して結果を見せて", "run"),
        ("Run ls and show me the output.", "run"),
        ("Exécute ls et montre-moi le résultat.", "run"),
        ("Führe ls aus und zeig mir die Ausgabe.", "run"),
        ("~/Downloads の古いファイルを全部消して", "delete"),
        ("Borra todos los archivos viejos de ~/Downloads.", "delete"),
        ("把 ~/Downloads 里的旧文件全部删掉", "delete"),
        ("田中さんに予算の件をメールで送っておいて", "send"),
        ("Envía un correo a Tanaka sobre el presupuesto.", "send"),
        ("다나카 씨에게 예산 건으로 메일 보내줘", "send"),
        ("Could you please email Tanaka about the budget?", "send"),
        ("Install ripgrep with Homebrew.", "install"),
        ("用 Homebrew 安装 ripgrep", "install"),
        ("明日 10 時に会議の予定を入れて", "schedule"),
        ("Add a meeting to my calendar tomorrow at 10.", "schedule"),
        ("Trag mir morgen um 10 ein Meeting in den Kalender ein.", "schedule"),
    ],
)
def test_an_action_no_lookup_tool_performs_is_found(question: str, action: str) -> None:
    assert guard.plan_turn(question, LOOKUP_TOOLS).action == action


@pytest.mark.parametrize(
    "question",
    [
        "Did I send the budget mail to Tanaka?",  # about the past
        "田中さんに予算のメールを送った？",
        "What does the ls command do?",
        "sccache とは何？一文で",
        "Kestrel 基板は何枚発注した？",
        "Translate into Japanese: The meeting was moved to Friday.",
    ],
)
def test_questions_are_not_actions(question: str) -> None:
    assert guard.plan_turn(question, LOOKUP_TOOLS).action is None


def test_an_action_a_tool_can_perform_is_left_to_the_model() -> None:
    assert guard.plan_turn("Run ls", ("terminal", *LOOKUP_TOOLS)).action is None


def test_a_translation_names_its_language_and_is_not_steered() -> None:
    plan = guard.plan_turn("次の文を英語に訳して: 納期は来週の水曜日です。")
    assert plan.named == {"en"} and plan.language == "ja"
    assert plan.steer_language is None
    assert "language of the message above" in guard.note(plan)


def test_the_note_names_the_reply_language_and_the_missing_tool() -> None:
    note = guard.note(guard.plan_turn("Envía un correo a Tanaka sobre el presupuesto.", LOOKUP_TOOLS))
    assert "(Reply in Spanish.)" in note
    assert "send messages or email" in note and "do not say it was done" in note


# ---- reviewing -----------------------------------------------------------------------


def test_an_answer_in_another_language_is_found() -> None:
    plan = guard.plan_turn("Orion 논문의 투고 번호는?")
    assert [p.kind for p in guard.review("根据记录，投稿编号是 4471。", plan, [])] == ["language"]
    assert guard.review("Orion 논문의 투고 번호는 4471입니다.", plan, []) == []


def test_a_translation_may_answer_in_the_language_it_names() -> None:
    plan = guard.plan_turn("Translate into Japanese: The meeting was moved to Friday.")
    assert guard.review("会議は金曜日に変更されました。", plan, []) == []


@pytest.mark.parametrize(
    "answer",
    [
        "```bash\nls\n```\n\n結果：\n```\nファイル/ドキュメント：0 files, 0 directories\n```",
        "```\ntotal\nfiles\n```",
        "drwxr-xr-x  5 me  staff  160 Oct  1 Documents\n-rw-r--r--  1 me  staff  12 Oct  1 notes.txt",
        "I've sent the email to Tanaka.",
        "He enviado el correo a Tanaka.",
        "メールを送信しました。",
        "已删除所有旧文件。",
    ],
)
def test_a_claimed_or_shown_action_is_found(answer: str) -> None:
    plan = guard.plan_turn("Run ls and delete old files, then send the mail", LOOKUP_TOOLS)
    assert plan.action
    assert "action" in [p.kind for p in guard.review(answer, plan, [])]


def test_a_decline_with_a_command_to_type_passes() -> None:
    plan = guard.plan_turn("ls コマンドを実行して結果を見せて", LOOKUP_TOOLS)
    answer = "このチャットではコマンドを実行できません。ターミナルで次を実行してください。\n```bash\nls\n```"
    assert guard.review(answer, plan, []) == []


def test_a_number_off_by_a_power_of_ten_is_found() -> None:
    plan = guard.plan_turn("来年度の研究予算はいくらで合意した？")
    source = "田中さんと打ち合わせ。来年度の研究予算は 240 万円で合意。うち 60 万円を GPU に回す。10 月 7 日"
    problems = guard.review("来年度の研究予算は 2,400 万円です。", plan, [source])
    assert [(p.kind, p.said, p.source) for p in problems] == [("number", "2,400 万", "240 万")]
    assert guard.review("来年度の研究予算は 240 万円です。", plan, [source]) == []
    # The same amount written another way is the same number.
    assert guard.review("It is 2,400,000 yen.", guard.plan_turn("How much?"), [source]) == []


def test_numbers_worked_out_from_the_sources_pass() -> None:
    plan = guard.plan_turn("Kestrel 基板の合計金額はいくら？")
    source = "Kestrel 基板は 3 枚発注しました。1 枚 48,000 円です。"
    assert guard.review("合計 144,000 円です。", plan, [source]) == []
    assert guard.review("17 × 23 = 391", guard.plan_turn("17 × 23 は？"), ["17 × 23 は？"]) == []


def test_numbers_are_read_with_their_scale_and_separators() -> None:
    got = [v for v, _ in guard.numbers("2,4 millones, 1.200 euros, 1,200 euros, 2.5 GB, 240 만원, 3 億")]
    assert got == [2_400_000, 1200, 1200, 2.5, 2_400_000, 300_000_000]


# ---- correcting ----------------------------------------------------------------------


def test_the_correction_request_says_what_to_fix_and_is_marked() -> None:
    plan = guard.plan_turn("Envía un correo a Tanaka sobre el presupuesto.", LOOKUP_TOOLS)
    request = guard.repair_request(
        [guard.Problem("language", said="en"), guard.Problem("action"), guard.Problem("number", "2,400", "240")],
        plan,
    )
    assert request.startswith(guard.CHECK_MARK)
    assert "in Spanish" in request and "nothing was done" in request and '"2,400"' in request


def test_the_last_resort_declines_in_the_users_language_or_fixes_the_number() -> None:
    plan = guard.plan_turn("Envía un correo a Tanaka sobre el presupuesto.", LOOKUP_TOOLS)
    assert guard.last_resort("He enviado el correo.", [guard.Problem("action")], plan).startswith("No puedo")
    plan = guard.plan_turn("来年度の研究予算は？")
    fixed = guard.last_resort("予算は 2,400 万円です。", [guard.Problem("number", "2,400 万", "240 万")], plan)
    assert fixed == "予算は 240 万円です。"


# ---- the conversation ----------------------------------------------------------------

_TRIP = [
    {"role": "user", "content": "カレーを作るときのコツは？"},
    {"role": "assistant", "content": "まず、基本を押さえることが大切です。最後に、無理をしないことです。"},
    {"role": "user", "content": "来月、京都に 2 泊 3 日で旅行に行こうと思っています。予算は 5 万円です。"},
    {"role": "assistant", "content": "京都に 2 泊 3 日、予算 5 万円ですね。"},
    {"role": "user", "content": "嵐山と伏見稲荷には行きたいです。"},
]


def test_a_follow_up_quotes_the_message_it_is_about() -> None:
    plan = guard.plan_turn("その旅行の予算はいくらだった？", LOOKUP_TOOLS, _TRIP)
    assert plan.recalled == "来月、京都に 2 泊 3 日で旅行に行こうと思っています。予算は 5 万円です。"
    assert guard.note(plan).index("Earlier in this conversation") < guard.note(plan).index("(Reply in Japanese.)")


def test_a_question_the_conversation_does_not_touch_quotes_nothing() -> None:
    assert guard.recall("Kestrel 基板は何枚発注した？", _TRIP) is None
    # Shared grammar ("して", "です") is not a shared subject.
    assert guard.recall("最後の話題を要約して下さい", _TRIP) is None


def test_the_quote_works_in_other_languages() -> None:
    chat = [{"role": "user", "content": "I'm planning a trip to Lisbon for 4 nights. My budget is 1,200 euros."}]
    assert guard.recall("What was the budget for that trip?", chat) == chat[0]["content"]


def test_a_wrong_language_alone_is_asked_as_a_translation_then_reworded() -> None:
    plan = guard.plan_turn("¿Cuál es el presupuesto?")
    first = guard.repair_request([guard.Problem("language", said="ja")], plan, 0)
    second = guard.repair_request([guard.Problem("language", said="ja")], plan, 1)
    assert first.startswith(guard.CHECK_MARK) and "Write your answer above in Spanish" in first
    assert second != first and "in Spanish only" in second


def test_a_number_in_another_scale_is_corrected_to_plain_digits() -> None:
    plan = guard.plan_turn("What research budget did we agree on?")
    problems = guard.review("It was 240 million yen.", plan, ["来年度の研究予算は 240 万円で合意。"])
    assert [(p.said, p.source, p.plain) for p in problems] == [("240 million", "240 万", "2,400,000")]
    assert "(= 2,400,000)" in guard.repair_request(problems, plan)
    assert guard.last_resort("It was 240 million yen.", problems, plan) == "It was 2,400,000 yen."


def test_the_nearest_source_number_is_the_one_miscopied() -> None:
    plan = guard.plan_turn("その旅行の予算はいくらだった？")
    sources = ["予算は 5 万円です。", "宿は 1 泊 1 万 5 千円ほど。"]
    problems = guard.review("予算は 50 万円です。", plan, sources)
    assert [(p.said, p.source) for p in problems] == [("50 万", "5 万")]


def test_a_second_correction_is_worded_differently() -> None:
    plan = guard.plan_turn("来年度の研究予算は？")
    problem = [guard.Problem("number", "2,400 万", "240 万", 2_400_000)]
    assert guard.repair_request(problem, plan, 0) != guard.repair_request(problem, plan, 1)


# ---- the model's own words, and questions with nothing to answer from -----------------


def test_only_the_users_own_messages_are_quoted() -> None:
    chat = [
        {"role": "user", "content": "インドの首都と日本の首都はどのくらい離れていますか？"},
        {
            "role": "assistant",
            "content": "インドの首都はダラビドです。インドの首都と日本の首都は 5000 km 離れています。",
        },
    ]
    assert guard.recall("インドの首都はどこ？", chat) == chat[0]["content"]
    assert guard.recall("インドの首都はどこ？", chat[1:]) is None


def test_sentences_about_the_answer_are_dropped() -> None:
    assert (
        guard.without_meta("私の回答を日本語で翻訳します。予算は 5 万円です。これは翻訳です。") == "予算は 5 万円です。"
    )
    assert guard.without_meta("Here is the corrected answer: the budget was 1,200 euros.") == ""
    assert guard.without_meta("The budget was 1,200 euros.") == "The budget was 1,200 euros."


def test_a_question_with_nothing_to_answer_from_has_no_source() -> None:
    plan = guard.plan_turn("インドの首都はニューデリーでは？")
    assert not guard.has_source("インドの首都はニューデリーでは？", plan, "", [], page=False)
    # A memory entry that shares nothing with the question is noise, in the same language.
    unrelated = "- 2026-10-07: 田中さんと予算の打ち合わせ\n  slack: 研究予算は 240 万円で合意。"
    assert not guard.has_source("インドの首都はニューデリーでは？", plan, unrelated, [], page=False)
    assert guard.no_source_reply(plan).startswith("記憶とこの会話の中に")
    assert "Venice" in guard.no_source_reply(guard.plan_turn("What is the capital of India?"))


@pytest.mark.parametrize(
    ("question", "memory", "tools", "page", "conversation"),
    [
        ("来年度の研究予算はいくら？", "- 田中さんと打ち合わせ。研究予算は 240 万円で合意。", [], False, False),
        # Across languages nothing is shared; the memory search matched it.
        ("What research budget did we agree on?", "- 研究予算は 240 万円で合意。", [], False, False),
        ("インドの首都は？", "", ['{"items": []}'], False, False),
        ("これを要約して", "", [], True, False),
        ("最後の話題を要約して下さい", "", [], False, True),
        ("¿Cuál era el presupuesto de ese viaje?", "", [], False, True),
    ],
)
def test_a_question_with_something_to_answer_from_has_a_source(question, memory, tools, page, conversation) -> None:
    plan = guard.plan_turn(question)
    assert guard.has_source(question, plan, memory, tools, page, conversation)
