"""No-model conformance: do the imported records and their head lines match the truth?

Mail: the real collector (``plan_import``) parses the generated mbox. Telegram:
the generated canonical records. For every imported part the truth predicts,
the check compares part kind, author (person) and owner class, verifies the
part text carries the predicted tokens, and renders the part with
``render_part`` to confirm the head line names the same speaker class and kind
(``account owner`` / ``unknown sender`` / the author's display name;
``quoted text`` / ``forwarded text``). Parts the importer produced but the
truth does not predict are reported as extras.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from mordred_hermes.imports.aliases import safe_display
from mordred_hermes.imports.records import ImportConversation, ImportMessage, ImportPart, PartKind
from mordred_hermes.imports.render import LABELS, SOURCE_LABELS, HeadStyle, render_part

from .context import mail_threads, person_of_part
from .encode_telegram import EncodedThread
from .generate import Dataset
from .tokens import find_tokens
from .truth import SOURCES, PartTruth, Truth

__all__ = ["ConformanceReport", "PartCheck", "run_conformance"]

_EN = LABELS["en"]


@dataclass(frozen=True, kw_only=True)
class PartCheck:
    source: str
    scenario: str
    thread_id: str
    evidence_id: str
    expected: str  # "kind/author/owner_class"
    actual: str
    tokens_ok: bool
    head_ok: bool

    @property
    def ok(self) -> bool:
        return self.expected == self.actual and self.tokens_ok and self.head_ok


@dataclass(frozen=True)
class ConformanceReport:
    checks: tuple[PartCheck, ...]
    extras: tuple[tuple[str, str], ...]  # (source, evidence id) produced but not predicted

    def accuracy(self, source: str | None = None, scenario: str | None = None) -> float:
        """Correct parts / (predicted parts + unpredicted extras) in the selection."""
        checks = [c for c in self.checks if source in (None, c.source) and scenario in (None, c.scenario)]
        extras = sum(1 for src, _eid in self.extras if source in (None, src)) if scenario is None else 0
        total = len(checks) + extras
        return 1.0 if total == 0 else sum(1 for check in checks if check.ok) / total

    def table(self) -> list[tuple[str, str, int, int]]:
        """(source, scenario, correct, total) rows."""
        totals: Counter[tuple[str, str]] = Counter()
        correct: Counter[tuple[str, str]] = Counter()
        for check in self.checks:
            totals[(check.source, check.scenario)] += 1
            correct[(check.source, check.scenario)] += check.ok
        return [(src, scenario, correct[(src, scenario)], total) for (src, scenario), total in sorted(totals.items())]

    def failures(self) -> list[PartCheck]:
        return [check for check in self.checks if not check.ok]


def _expected(part: PartTruth) -> str:
    author = part.author if part.author_knowable else "-"
    return f"{part.kind}/{author}/{part.owner_class}"


def _actual(truth: Truth, source: str, part: ImportPart) -> str:
    person = person_of_part(truth, source, part)
    return f"{part.part_kind}/{person or '-'}/{part.author_owner_class}"


def _head_ok(
    conv: ImportConversation, msg: ImportMessage, part: ImportPart, predicted: PartTruth, truth: Truth
) -> bool:
    head = render_part(conv, msg, part, style=HeadStyle.PER_PART_EN).head
    prefix = f"[{SOURCE_LABELS[conv.source]} {predicted.evidence_id}] {_EN['speaker']}: "
    if not head.startswith(prefix):
        return False
    speaker = head[len(prefix) :].split(" → ", 1)[0]
    kind_ok = (_EN["forwarded"] in speaker) == (predicted.kind == PartKind.FORWARDED) and (
        _EN["quoted"] in speaker
    ) == (predicted.kind == PartKind.QUOTED)
    if not predicted.author_knowable:
        expected_speaker = _EN["unknown_sender"]
    elif predicted.owner_class == "account_owner":
        expected_speaker = _EN["owner"]
    else:
        expected_speaker = safe_display(predicted.author_name)
    return kind_ok and speaker.startswith(expected_speaker)


def _index(threads: Iterable[EncodedThread]) -> dict[str, tuple[ImportConversation, ImportMessage, ImportPart]]:
    return {
        part.part_uid: (thread.conversation, msg, part)
        for thread in threads
        for msg in thread.messages
        for part in msg.parts
    }


def run_conformance(dataset: Dataset, *, mail: Mapping[str, EncodedThread] | None = None) -> ConformanceReport:
    """Compare the imported records of both sources with the truth (no model involved)."""
    truth = dataset.truth
    imported = {
        "telegram": _index(dataset.telegram),
        "mail": _index((mail if mail is not None else mail_threads(truth, dataset.mail_mbox)).values()),
    }
    scenarios = {thread.thread_id: thread.scenario for thread in truth.threads}
    checks: list[PartCheck] = []
    for predicted in truth.parts:
        if not predicted.imported:
            continue
        found = imported[predicted.source].pop(predicted.evidence_id, None)
        if found is None:
            actual, tokens_ok, head_ok = "missing", False, False
        else:
            conv, msg, part = found
            actual = _actual(truth, predicted.source, part)
            tokens_ok = set(predicted.tokens) <= set(find_tokens(part.text))
            head_ok = _head_ok(conv, msg, part, predicted, truth)
        checks.append(
            PartCheck(
                source=predicted.source,
                scenario=scenarios[predicted.thread_id],
                thread_id=predicted.thread_id,
                evidence_id=predicted.evidence_id,
                expected=_expected(predicted),
                actual=actual,
                tokens_ok=tokens_ok,
                head_ok=head_ok,
            )
        )
    extras = tuple((source, uid) for source in SOURCES for uid in sorted(imported[source]))
    return ConformanceReport(tuple(checks), extras)
