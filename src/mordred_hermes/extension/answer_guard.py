"""Python checks around one extension chat turn, for a small local model.

A 2B model follows a short rule list only loosely: it drifts to the language of
the rules or of a long history, writes the output of a command no tool ran, and
copies a number off by a factor of ten. Each of those can be told from the text
without a model, so the chat:

1. **plans** the turn from the user's words (:func:`plan_turn`): the language to
   reply in, the languages a translation asks for, and an action the offered tools
   cannot perform (run a command, delete, send, install, schedule);
2. **steers** the model with a short note after those words (:func:`note`);
3. **reviews** the answer (:func:`review`): its language, a claimed or
   fabricated action, and a number that is a slip of one in the sources;
4. asks the model once to **correct** what the review found
   (:func:`repair_request`), and as a **last resort** replaces what is still
   wrong (:func:`last_resort`).

The logic is the same for every language; only the word tables are per language,
and an unknown language turns the language steps off instead of guessing.
"""

# ruff: noqa: RUF001 - word tables and replies in many scripts use full-width punctuation on purpose

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import combinations_with_replacement
from typing import Final

from ..recall.turn_context import CHECK_MARK
from ..text_language import content_units, detect, name

# ---- what the user asks for ------------------------------------------------------------

#: Language names, as users write them, to the language they name (a translation target).
_LANGUAGE_NAMES: Final[dict[str, tuple[str, ...]]] = {
    "en": ("english", "englisch", "inglés", "ingles", "anglais", "inglês", "inglese", "英語", "英语", "英文", "영어"),
    "ja": ("japanese", "japanisch", "japonés", "japonais", "japonês", "giapponese", "日本語", "日语", "日文", "일본어"),
    "ko": ("korean", "koreanisch", "coreano", "coréen", "韓国語", "韩语", "韓語", "한국어"),
    "zh": (
        "chinese",
        "chinesisch",
        "chino",
        "chinois",
        "chinês",
        "cinese",
        "中国語",
        "中文",
        "汉语",
        "中國語",
        "중국어",
    ),
    "es": ("spanish", "spanisch", "español", "espagnol", "espanhol", "spagnolo", "スペイン語", "西班牙语", "스페인어"),
    "fr": ("french", "französisch", "francés", "français", "francês", "francese", "フランス語", "法语", "프랑스어"),
    "de": ("german", "deutsch", "alemán", "allemand", "alemão", "tedesco", "ドイツ語", "德语", "독일어"),
    "pt": (
        "portuguese",
        "portugiesisch",
        "portugués",
        "portugais",
        "português",
        "portoghese",
        "ポルトガル語",
        "葡萄牙语",
        "포르투갈어",
    ),
    "it": ("italian", "italienisch", "italiano", "italien", "イタリア語", "意大利语", "이탈리아어"),
}

# Requests for an action, by kind. Latin-script patterns are matched at the start of
# a sentence (an imperative, or "can you ..."), so "Did I send it?" is a question
# about the past, not a request. CJK patterns match the request form of the verb.
_PLEASE = r"(?:(?:please|por favor|s'il te pla[iî]t|s'il vous pla[iî]t|bitte|per favore)[,\s]+)?"
_CAN_YOU = (
    r"(?:(?:can|could|would|will) you\s+(?:please\s+)?|(?:puedes|podr[ií]as)\s+|(?:peux|pourrais)-tu\s+"
    r"|(?:pouvez|pourriez)-vous\s+|kannst du\s+|k[öo]nnten sie\s+|(?:pode|poderia)s?\s+|(?:puoi|potresti)\s+)?"
)
_ACTIONS: Final[dict[str, tuple[str, ...]]] = {
    "run": (
        r"(?:run|execute|ejecuta|ejecutar|corre|ex[ée]cute[rz]?|lance[rz]?|f[üu]hre\b.*\baus|ausf[üu]hren|rode|roda|executar|esegui|eseguire)\b",
        r"(?:実行|起動)し(?:て|ておいて)",
        r"실행(?:해|하여|시켜)",
        r"(?:帮我|请)?(?:运行|执行)(?!.*(?:怎么|如何|什么是))",
    ),
    "delete": (
        r"(?:delete|remove|erase|wipe|borra|borrar|elimina|eliminar|supprime[rz]?|efface[rz]?"
        r"|l[öo]sch(?:e|en)|entfern(?:e|en)|apag(?:a|ue|ar)|exclu(?:a|ir)|remova|cancella|cancellare)\b",
        r"(?:消し|削除し)(?:て|ておいて)",
        r"(?:삭제|지워)(?:해|줘| 줘|주세요)",
        r"(?:删掉|删除|删了)",
    ),
    "send": (
        r"(?:send|e-?mail|text|forward|reply to|env[ií]a|enviar|manda|mandar|reenv[ií]a|envoie[rz]?|envoyer"
        r"|transf[èe]re[rz]?|sende|senden|schick(?:e|en)?|mande|envie|invia|inviare)\b",
        r"(?:送っ|送信し|転送し|返信し)(?:て|ておいて)",
        r"보내(?:줘| 줘|주세요|줄래)",
        r"(?:发送|发给|发邮件|发消息|寄给|回复给)",
    ),
    "install": (
        r"(?:install|uninstall|instala|instalar|installe[rz]?|installier(?:e|en)|instale|installa|installare)\b",
        r"(?:アン)?インストールし(?:て|ておいて)",
        r"설치(?:해|하여)",
        r"(?:安装|卸载)",
    ),
    "schedule": (
        r"(?:(?:add|put|schedule|book|set)\b.*\b(?:calendar|meeting|appointment|reminder|alarm|event)"
        r"|remind me|(?:pon|agenda|a[ñn]ade|programa|reserva)\b.*\b(?:calendario|reuni[óo]n|cita|recordatorio)"
        r"|(?:ajoute|mets|planifie|r[ée]serve)\b.*\b(?:agenda|calendrier|r[ée]union|rendez-vous|rappel)"
        r"|(?:trag|f[üu]ge|plane|buche)\b.*\b(?:kalender|meeting|termin|erinnerung)"
        r"|(?:agende|marque|adicione|coloque)\b.*\b(?:calend[áa]rio|reuni[ãa]o|compromisso|lembrete)"
        r"|(?:aggiungi|programma|prenota)\b.*\b(?:calendario|riunione|appuntamento|promemoria))",
        r"(?:予定|会議|ミーティング|リマインダー|アラーム).{0,12}(?:入れ|登録し|追加し|設定し)(?:て|ておいて)|予約し(?:て|ておいて)",
        r"(?:일정|회의|알림|미팅).{0,12}(?:넣어|추가해|잡아|등록해)|예약해",
        r"(?:日历|日程|会议|提醒).{0,12}(?:加上|添加|安排|设置)|预约|设个提醒",
    ),
}
#: What each action is, for the note to the model.
_ACTION_WHAT: Final[dict[str, str]] = {
    "run": "run commands or programs",
    "delete": "delete or change files or data",
    "send": "send messages or email",
    "install": "install or remove software",
    "schedule": "change a calendar or set reminders",
}
#: A tool whose name has one of these words can perform the action; then nothing is blocked.
_TOOL_WORDS: Final[dict[str, tuple[str, ...]]] = {
    "run": ("terminal", "shell", "exec", "command", "code_execution", "process"),
    "delete": ("delete", "remove", "write_file", "patch", "terminal", "shell"),
    "send": ("send", "mail_send", "post_message", "reply"),
    "install": ("terminal", "shell", "install"),
    "schedule": ("calendar", "schedule", "cron", "reminder"),
}
_CJK = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]")


@dataclass(frozen=True)
class TurnPlan:
    """What a turn asks for, decided from the user's words before the model runs."""

    language: str | None = None
    named: frozenset[str] = field(default_factory=frozenset)
    action: str | None = None
    #: The earlier message of this conversation the question is about, quoted for the model.
    recalled: str | None = None

    @property
    def steer_language(self) -> str | None:
        """The language to ask for, unless the user names one (a translation decides it)."""
        return None if self.named else self.language


#: How much of the question an earlier message must cover to be quoted back (see :func:`recall`).
RECALL_MIN_UNITS: Final = 2
RECALL_MIN_SHARE: Final = 0.2
RECALL_MESSAGES: Final = 8
RECALL_CHARS: Final = 300


def plan_turn(question: str, tool_names: Iterable[str] = (), history: Iterable[dict] = ()) -> TurnPlan:
    """The language, the named languages, an unsupported action and the earlier message ``question`` is about."""
    lower = question.lower()
    named = frozenset(code for code, names in _LANGUAGE_NAMES.items() if any(n in lower for n in names))
    action = requested_action(question)
    if action and any(word in tool.lower() for tool in tool_names for word in _TOOL_WORDS[action]):
        action = None
    return TurnPlan(language=detect(question), named=named, action=action, recalled=recall(question, history))


def recall(question: str, history: Iterable[dict]) -> str | None:
    """The recent message that shares the most with ``question``, when it shares enough.

    A small model asked "what was the budget for that trip?" a few turns after the
    trip was planned often answers that it has no record; quoting the user's message
    that planned it next to the question puts the answer where the model looks. Shared
    units are counted with :func:`..text_language.content_units`, so this works the
    same in every language; a question the conversation does not touch quotes nothing.
    """
    asked = content_units(question)
    if not asked:
        return None
    # The user's own words only: quoting the model's earlier answer would hand a wrong
    # answer back to it as if it were a fact.
    msgs = [
        m
        for m in list(history)[-RECALL_MESSAGES:]
        if isinstance(m, dict) and m.get("role") == "user" and isinstance(m.get("content"), str)
    ]
    best, best_text = 0, None
    for msg in msgs:
        shared = len(asked & content_units(msg["content"]))
        if shared > best:
            best, best_text = shared, msg["content"]
    if best_text is None or best < RECALL_MIN_UNITS or best < RECALL_MIN_SHARE * len(asked):
        return None
    flat = " ".join(best_text.split())
    return flat if len(flat) <= RECALL_CHARS else f"{flat[:RECALL_CHARS]}…"


def requested_action(question: str) -> str | None:
    """The kind of action ``question`` asks the chat to perform, if any."""
    sentences = [s.strip() for s in re.split(r"[.!?\n。！？]+", question) if s.strip()]
    for kind, (latin, ja, ko, zh) in _ACTIONS.items():
        latin_at_start = re.compile(rf"^{_PLEASE}{_CAN_YOU}{latin}", re.I)
        if any(latin_at_start.search(s) for s in sentences):
            return kind
        if _CJK.search(question) and any(re.search(p, question) for p in (ja, ko, zh)):
            return kind
    return None


def note(plan: TurnPlan) -> str:
    """The note sent after the user's words (the model's copy only)."""
    lang = name(plan.steer_language)
    parts = []
    if plan.recalled:
        parts.append(f'(Earlier in this conversation: "{plan.recalled}")')
    parts.append(f"(Reply in {lang}.)" if lang else "(Reply in the language of the message above.)")
    if plan.action:
        in_lang = f" in {lang}" if lang else ""
        parts.append(
            f"(No tool here can {_ACTION_WHAT[plan.action]}. Say{in_lang}, in one or two sentences, that you "
            "cannot do it from this chat. Do not write any output, file names or results, and do not say it "
            "was done. You may offer to help with the wording or the steps instead.)"
        )
    return "\n\n" + "\n".join(parts)


# ---- what the answer says --------------------------------------------------------------

#: An answer that says an action was done (in the user's language or another).
_CLAIMED: Final = re.compile(
    r"\bi(?:'ve| have)?\s+(?:just\s+)?(?:sent|deleted|removed|ran|run|executed|installed|added|scheduled|booked)\b"
    r"|\b(?:has|have) been (?:sent|deleted|removed|installed|added|scheduled)\b"
    r"|\bhe (?:enviado|borrado|eliminado|ejecutado|instalado|a[ñn]adido|agendado)\b"
    r"|\b(?:ha sido|fue) (?:enviado|borrado|eliminado|instalado)\b"
    r"|\bj'ai (?:envoy[ée]|supprim[ée]|ex[ée]cut[ée]|install[ée]|ajout[ée])"
    r"|\ba [ée]t[ée] (?:envoy[ée]|supprim[ée]|install[ée]|ajout[ée])"
    r"|\b(?:habe|hab)\b.{0,40}\b(?:gesendet|geschickt|gel[öo]scht|ausgef[üu]hrt|installiert|eingetragen|hinzugef[üu]gt)\b"
    r"|\bwurde(?:n)? (?:gesendet|gel[öo]scht|installiert|eingetragen)\b"
    r"|\b(?:enviei|apaguei|exclu[ií]|executei|instalei|adicionei|agendei)\b"
    r"|\bho (?:inviato|cancellato|eliminato|eseguito|installato|aggiunto)\b"
    r"|(?:送信し|送り|削除し|消し|実行し|インストールし|登録し|追加し|入れ|設定し|完了し)ました(?!か)"
    r"|(?:보냈|삭제했|지웠|실행했|설치했|추가했|등록했)(?:습니다|어요)"
    r"|已(?:发送|删除|执行|安装|添加|设置)|(?:发送|删除|安装)成功",
    re.I,
)
#: Output only a run command could have produced: an ``ls -l`` row, a "total N" line.
_LISTING: Final = re.compile(r"(?m)^\s*[dl-][rwx-]{9}[@+.]?\s|^\s*total(?: \d+)?\s*$")
_CODE_BLOCK: Final = re.compile(r"```[^\n`]*\n(.*?)```", re.S)
#: A line that is just a file or directory name.
_FILE_LINE: Final = re.compile(r"(?m)^\s*(?:[-*]\s+)?[\w.~/-]+(?:\.\w{1,6}|/)\s*$")

_NUMBER: Final = re.compile(
    r"(?<![\w.,])(\d{1,3}(?:[,\u00a0\u202f ]\d{3})+(?![\d.,]\d)|\d{1,3}(?:\.\d{3})+(?![\d,]\d)|\d+(?:[.,]\d+)?)"
    r"\s*(万|億|千|만|억|천|百万|千万|millions?|millones|milh[õo]es|millionen|milioni|mio\b|million\b)?",
    re.I,
)
_SCALE: Final = {"万": 1e4, "만": 1e4, "億": 1e8, "억": 1e8, "千": 1e3, "천": 1e3, "百万": 1e6, "千万": 1e7}


@dataclass(frozen=True)
class Problem:
    kind: str  # "language" | "action" | "number"
    said: str = ""
    source: str = ""
    #: The source number's value, written without a scale word for any language.
    value: float = 0.0

    @property
    def plain(self) -> str:
        return f"{self.value:,.0f}" if self.value == int(self.value) else f"{self.value:,}"


def numbers(text: str) -> list[tuple[float, str]]:
    """``(value, as written)`` for each number in ``text``, with 万/억/million scales applied."""
    found = []
    for m in _NUMBER.finditer(text):
        digits, scale = m.group(1), (m.group(2) or "").lower()
        # A separator before exactly three digits groups thousands ("1,200", "1.200"); otherwise
        # it is a decimal mark ("2,4 millones", "2.5").
        if re.fullmatch(r"\d{1,3}(?:[,.\u00a0\u202f ]\d{3})+", digits):
            value = float(re.sub(r"\D", "", digits))
        else:
            value = float(digits.replace(",", "."))
        value *= _SCALE.get(scale, 1e6 if scale.startswith(("mill", "milh", "mio")) else 1)
        found.append((value, m.group(0).strip()))
    return found


def _power_of_ten(x: float) -> bool:
    return x >= 10 and any(abs(x - 10**k) < 1e-9 for k in range(1, 13))


def _derivable(values: list[float]) -> set[float]:
    """The values, and the sums, differences, products and whole quotients of two of them.

    Scaling by a power of ten is left out: that is the miscopy being looked for, and
    a "10" is in almost every source (a date, a count).
    """
    pool = sorted(set(values))[:80]
    out = set(pool)
    for a, b in combinations_with_replacement(pool, 2):
        out.update({a + b, abs(a - b)})
        if _power_of_ten(a) or _power_of_ten(b):
            continue
        out.add(a * b)
        if b and a % b == 0:
            out.add(a / b)
        if a and b % a == 0:
            out.add(b / a)
    return out


def _slip(value: float, source: float) -> bool:
    """``value`` looks like a miscopy of ``source``: a power of ten off, or the same digits reordered."""
    if value == source or not value or not source:
        return False
    ratio = max(value, source) / min(value, source)
    if any(abs(ratio - 10**k) < 1e-9 for k in range(1, 5)):
        return True
    a, b = f"{value:.0f}", f"{source:.0f}"
    return len(a) >= 3 and a != b and sorted(a) == sorted(b)


def _shows_output(answer: str) -> bool:
    """A code block beyond the one command the user could type: the "result" of running it."""
    blocks = [b for b in _CODE_BLOCK.findall(answer) if b.strip()]
    return len(blocks) >= 2 or any(len([ln for ln in b.splitlines() if ln.strip()]) >= 2 for b in blocks)


def _distance(value: float, source: float) -> float:
    """How far apart two numbers are in powers of ten (0 for reordered digits)."""
    return abs(math.log10(value / source))


def review(answer: str, plan: TurnPlan, sources: Iterable[str]) -> list[Problem]:
    """What is wrong with ``answer``: its language, a claimed action, a miscopied number."""
    problems: list[Problem] = []
    if plan.language and not plan.named:
        got = detect(answer)
        if got and got != plan.language:
            problems.append(Problem("language", said=got))
    if plan.action and (
        _CLAIMED.search(answer)
        or _LISTING.search(answer)
        or len(_FILE_LINE.findall(answer)) >= 3
        or _shows_output(answer)
    ):
        problems.append(Problem("action"))
    source_numbers = [n for text in sources for n in numbers(text)]
    allowed = _derivable([v for v, _ in source_numbers])
    for value, written in numbers(answer):
        if value < 10 or value in allowed:
            continue
        # The nearest miscopy wins: "50 万" is 5 万 one power of ten off before it is 5 千 two off.
        slips = sorted((_distance(value, v), v, w) for v, w in source_numbers if _slip(value, v))
        nearest = [s for s in slips if s[0] == slips[0][0]] if slips else []
        if nearest and len({v for _d, v, _w in nearest}) == 1:
            _d, source_value, source = nearest[0]
            problems.append(Problem("number", said=written, source=source, value=source_value))
    return problems


def repair_request(problems: list[Problem], plan: TurnPlan, attempt: int = 0) -> str:
    """The message asking the model to correct its answer (not searched, not shown).

    A wrong language alone is asked as a translation, which a small model does
    reliably and does not echo; a second attempt is worded differently, because the
    same request gets the same answer from a model that samples deterministically.
    """
    lang = name(plan.language) if not plan.named else None
    if lang and {p.kind for p in problems} == {"language"}:
        if attempt == 0:
            alone = "Reply with that text alone, nothing before or after it."
            return f"{CHECK_MARK} Write your answer above in {lang}. {alone}"
        return f"{CHECK_MARK} Answer the question again, in {lang} only, in one or two sentences."
    lines = [
        f"{CHECK_MARK} Your answer above needs fixing:"
        if attempt == 0
        else f"{CHECK_MARK} Answer the question again in one or two sentences. Mind that:"
    ]
    for p in problems:
        if p.kind == "language" and lang:
            lines.append(f"- It is not in {lang}. The user wrote in {lang}; write the whole answer in {lang}.")
        elif p.kind == "action" and plan.action:
            lines.append(
                f"- No tool here can {_ACTION_WHAT[plan.action]}, and nothing was done. Do not show output or "
                "say it was done; say you cannot do it from this chat."
            )
        elif p.kind == "number":
            lines.append(
                f'- It says "{p.said}", but the sources say "{p.source}" (= {p.plain}).'
                " Use the number the sources give."
            )
    lines.append(f"Write only the corrected answer{f', in {lang}' if lang else ''}.")
    return "\n".join(lines)


#: The last-resort reply to an action no tool can perform, per language.
_CANNOT: Final[dict[str, str]] = {
    "en": ("I can't do that from this chat: its tools can only look things up, not act on your computer or accounts."),
    "ja": (
        "このチャットではそれはできません。"
        "使える道具は調べることだけで、パソコンやアカウントを操作することはできません。"
    ),
    "es": (
        "No puedo hacer eso desde este chat: sus herramientas solo buscan información,"
        " no actúan en tu equipo ni en tus cuentas."
    ),
    "fr": (
        "Je ne peux pas faire cela depuis ce chat : ses outils servent seulement à"
        " chercher, pas à agir sur votre ordinateur ou vos comptes."
    ),
    "de": (
        "Das kann ich in diesem Chat nicht tun: Seine Werkzeuge können nur nachschlagen,"
        " nicht auf deinem Computer oder deinen Konten handeln."
    ),
    "pt": (
        "Não posso fazer isso por este chat: as ferramentas dele só pesquisam, não agem"
        " no seu computador nem nas suas contas."
    ),
    "it": (
        "Non posso farlo da questa chat: i suoi strumenti possono solo cercare, non"
        " agire sul tuo computer o sui tuoi account."
    ),
    "ko": (
        "이 채팅에서는 그 작업을 할 수 없습니다."
        " 사용할 수 있는 도구는 찾아보는 것뿐이고, 컴퓨터나 계정을 조작할 수는 없습니다."
    ),
    "zh": "我无法在这个聊天中做到这一点：这里的工具只能查找信息，不能操作你的电脑或账户。",
}


def last_resort(answer: str, problems: list[Problem], plan: TurnPlan) -> str:
    """``answer`` with what a correction left wrong replaced by what is known to be true."""
    if any(p.kind == "action" for p in problems):
        return _CANNOT.get(plan.language or "", _CANNOT["en"])
    return fix_numbers(answer, problems)


def fix_numbers(answer: str, problems: list[Problem]) -> str:
    """``answer`` with each miscopied number replaced by the source's."""
    for p in problems:
        if p.kind == "number" and answer.count(p.said) == 1:
            # "2,400 万" → "240 万" where the answer counts in the same scale words;
            # "240 million" → "2,400,000" where it does not.
            same_scale = _scale_word(p.said) and _scale_word(p.said) == _scale_word(p.source)
            answer = answer.replace(p.said, p.source if same_scale else p.plain)
    return answer


def _scale_word(written: str) -> str:
    m = _NUMBER.fullmatch(written)
    return (m.group(2) or "").lower() if m else ""


# ---- talk about the answer, and questions with nothing to answer from ------------------

#: A sentence about the answer instead of the answer ("This is the translation.",
#: "回答は修正されます"): a small model echoing the correction request.
_META: Final = re.compile(
    r"(?:回答|答え)(?:は|を|が)?(?:修正|訂正|翻訳|書き直)|翻訳(?:します|しました|です)|これは翻訳|[日英]本?語で(?:回答|答え)(?:します|ます)"
    r"|\b(?:corrected|revised|translated) (?:answer|version|text)\b|\bhere is the (?:translation|corrected|revised)\b"
    r"|\bmy (?:previous|earlier|original) answer\b|\bthe answer above\b"
    r"|respuesta (?:corregida|anterior)|aqu[ií] est[áa] la traducci[óo]n|r[ée]ponse (?:corrig[ée]e|pr[ée]c[ée]dente)"
    r"|voici la traduction|korrigierte antwort|hier ist die [üu]bersetzung|resposta (?:corrigida|anterior)"
    r"|aqui est[áa] a tradu[çc][ãa]o|risposta corretta|ecco la traduzione"
    r"|수정된 (?:답변|대답)|번역(?:입니다|합니다|했습니다)|修正后的回答|以下是翻译|翻译如下|这是翻译",
    re.I,
)
_SENTENCE: Final = re.compile(r"[^。．.!?！？\n]+[。．.!?！？]?\n?")


def without_meta(text: str) -> str:
    """``text`` without its sentences about the answer itself."""
    kept = [s for s in _SENTENCE.findall(text) if not _META.search(s)]
    return "".join(kept).strip()


#: The reply when nothing (memory, tools, this conversation, the page) holds an answer and
#: the chat runs on a small local model, which would otherwise answer from what it half
#: knows. It points to the setting that changes the chat's model.
_NO_SOURCE: Final[dict[str, str]] = {
    "en": (
        "I couldn't find anything about this in your memory or in this conversation. The current chat AI is a"
        " small model on this computer, made for searching your memory, so it can't answer general questions"
        " reliably. To ask general questions too, upgrade the chat AI under Settings → Chat AI"
        " (recommended: Venice)."
    ),
    "ja": (
        "記憶とこの会話の中に、この質問の答えになるものが見つかりませんでした。今のチャット AI は"
        "このパソコンの中で動く小さなモデルで、記憶の検索のためのものなので、一般的な質問には正しく答えられません。"
        "一般的な質問にも答えさせるには、設定の「チャット AI」からアップグレードできます（おすすめ: Venice）。"
    ),
    "es": (
        "No encontré nada sobre esto en tu memoria ni en esta conversación. La IA del chat actual es un modelo"
        " pequeño en este equipo, pensado para buscar en tu memoria, así que no responde bien a preguntas generales."
        " Para hacer preguntas generales, mejora la IA del chat en Ajustes → IA del chat (recomendado: Venice)."
    ),
    "fr": (
        "Je n'ai rien trouvé à ce sujet dans votre mémoire ni dans cette conversation. L'IA du chat actuelle est un"
        " petit modèle sur cet ordinateur, conçu pour chercher dans votre mémoire : elle ne répond pas de façon"
        " fiable aux questions générales. Pour poser des questions générales, passez à une IA plus puissante dans"
        " Réglages → IA du chat (recommandé : Venice)."
    ),
    "de": (
        "Dazu habe ich weder in deinem Gedächtnis noch in diesem Gespräch etwas gefunden. Die aktuelle Chat-KI ist"
        " ein kleines Modell auf diesem Computer, gemacht für die Suche in deinem Gedächtnis; allgemeine Fragen"
        " beantwortet sie nicht zuverlässig. Für allgemeine Fragen kannst du die Chat-KI unter Einstellungen →"
        " Chat-KI aufrüsten (empfohlen: Venice)."
    ),
    "pt": (
        "Não encontrei nada sobre isso na sua memória nem nesta conversa. A IA do chat atual é um modelo pequeno"
        " neste computador, feito para pesquisar a sua memória, por isso não responde bem a perguntas gerais. Para"
        " fazer perguntas gerais, melhore a IA do chat em Configurações → IA do chat (recomendado: Venice)."
    ),
    "it": (
        "Non ho trovato nulla su questo nella tua memoria né in questa conversazione. L'IA della chat attuale è un"
        " piccolo modello su questo computer, pensato per cercare nella tua memoria, quindi non risponde bene alle"
        " domande generali. Per le domande generali, potenzia l'IA della chat in Impostazioni → IA della chat"
        " (consigliato: Venice)."
    ),
    "ko": (
        "기억과 이 대화에서 이 질문에 대한 답을 찾지 못했습니다. 지금의 채팅 AI는 이 컴퓨터에서 동작하는 작은 모델로,"
        " 기억 검색을 위한 것이라 일반적인 질문에는 정확히 답할 수 없습니다. 일반적인 질문에도 답하게 하려면 설정의"
        " '채팅 AI'에서 업그레이드할 수 있습니다(추천: Venice)."
    ),
    "zh": (
        "在你的记忆和这次对话中，没有找到能回答这个问题的内容。当前的聊天 AI 是在这台电脑上运行的小模型，"
        "用于搜索你的记忆，无法准确回答一般性问题。若要回答一般性问题，可在设置的“聊天 AI”中升级（推荐：Venice）。"
    ),
}


def no_source_reply(plan: TurnPlan) -> str:
    """What the chat says when nothing it was given answers the question."""
    return _NO_SOURCE.get(plan.language or "", _NO_SOURCE["en"])


#: A question about the conversation itself: asks for a summary, points back ("that
#: trip", "what did I say"), or refers to what was said earlier.
_ABOUT_CHAT: Final = re.compile(
    r"要約|まとめ|その|あの|さっき|先ほど|前に(?:言|話)|話した|言った"
    r"|\b(?:summari[sz]e|summary|recap|earlier|before|above|that|those|you said|i said|did i (?:say|mention|tell))\b"
    r"|\b(?:resum(?:e|en|ir)|res[úu]melo|ese|esa|esos|esas|aquel|antes|dijiste|dije)\b"
    r"|\b(?:r[ée]sum[ée]|r[ée]sume[rz]?|ce|cet|cette|ces|plus t[ôo]t|tu as dit|j'ai dit)\b"
    r"|\b(?:zusammenfass\w*|dies(?:e[rsnm]?)?|jene[rsnm]?|vorhin|du hast gesagt|ich habe gesagt)\b"
    r"|\b(?:resum[oa]|resumir|esse|essa|esses|essas|aquele|aquela|voc[êe] disse|eu disse)\b"
    r"|\b(?:riassum\w*|quel(?:lo|la)?|prima|hai detto|ho detto)\b"
    r"|요약|정리해|그 |아까|전에|말했"
    r"|总结|概括|那个|那次|这个|刚才|之前|你说|我说",
    re.I,
)


def has_source(
    question: str,
    plan: TurnPlan,
    memory: str,
    tool_results: Iterable[str],
    page: bool,
    conversation: bool = False,
) -> bool:
    """Whether the turn has something to answer from besides the model's own knowledge.

    That is: a memory entry sharing a unit with the question, a tool result, the
    user's earlier message (:func:`recall`), a question about the conversation (when
    there is one), the page the user is on, or text the user gave to translate.
    """
    if plan.recalled or page or plan.named or any(t.strip() for t in tool_results):
        return True
    if conversation and _ABOUT_CHAT.search(question):
        return True
    if not memory:
        return False
    # Across languages no words are shared; the memory search matched it, so it counts.
    # In the same language, an entry that shares nothing with the question is noise.
    if detect(memory) != plan.language:
        return True
    return bool(content_units(question) & content_units(memory))
