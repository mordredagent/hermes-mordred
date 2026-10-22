"""``hermes-mordred activity`` correction and lesson commands (the operator side of the correction loop).

- ``correct --episode ID --text TEXT [--attempt ID]`` — record an explicit correction and print the
  deterministic candidate lesson it implies.
- ``candidates build --episode ID [--correction EVENT_ID]`` — (re)build the deterministic candidate of
  each correction of an episode, e.g. one the collector recorded before its task boundary arrived.
- ``candidates list|show`` / ``lessons list|show`` — lesson identifiers and states; ``show`` prints every
  lesson field (user-authored), the evidence digest and evidence as ``event_id phase op site route``
  lines. Event ``target`` / ``text`` are never printed.
- ``validate``, ``adopt``, ``reject``, ``lessons suspend``, ``lessons retire``, ``lessons revise`` — state
  transitions.
  ``adopt`` without ``--digest`` shows the evidence digest and asks the operator to type its first
  12 characters; without a terminal it exits 2.

Every command opens the store through the protection gate and prints only the refusal code when
it refuses (exit 1).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import _term

if TYPE_CHECKING:
    from ..activity.config import ActivityConfig
    from ..activity.lessons import EvidenceRow, LessonRevision
    from ..activity.store import ActivityStore

_CANDIDATE_STATES = ("candidate", "validated")
_SHOWN_FIELDS = (
    "origin",
    "episode_id",
    "scope_site",
    "scope_route",
    "scope_task",
    "applies_when",
    "does_not_apply",
    "check_before_use",
    "guidance",
    "success_measure",
    "evidence_digest",
    "validation_method",
    "validation_note",
    "validated_at",
    "adopted_at",
    "adoption_digest",
    "suspended_reason",
    "superseded_by",
    "created_at",
)


# --------------------------------------------------------------------------- #
# Seams (module-level so tests can replace them)
# --------------------------------------------------------------------------- #


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _open(home: Path) -> tuple[ActivityStore, ActivityConfig]:
    from ..activity._gate import open_store
    from ..activity.config import ActivityConfig

    return open_store(home), ActivityConfig.load(home)


def _is_tty() -> bool:
    return sys.stdin.isatty()


def _read_line(prompt: str) -> str:
    return input(prompt)


def _display(value: object, limit: int = 1200) -> str:
    """Same-user-writable state is escaped before it reaches the terminal."""
    text = "-" if value is None else str(value)[:limit]
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _refused(exc: BaseException) -> int:
    code = getattr(exc, "code", None)
    _term.emit_error(f"refused ({_display(code if isinstance(code, str) else 'store_unavailable', 64)})")
    return 1


def _guarded(handler: Callable[[argparse.Namespace, ActivityStore, ActivityConfig], int]) -> Callable[..., int]:
    def run(args: argparse.Namespace) -> int:
        from ..activity._gate import ActivityRefused

        try:
            store, config = _open(_home())
            return handler(args, store, config)
        except ActivityRefused as exc:
            return _refused(exc)

    return run


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #


def _print_rows(rows: list[LessonRevision]) -> None:
    if not rows:
        print("  (none)")
        return
    for row in rows:
        print(
            f"  {_display(row.lesson_id, 64)}  rev {row.revision}  {row.state:<9}  "
            f"{_display(row.scope_site, 80)}{_display(row.scope_route or '', 80)}"
        )


def _print_lesson(lesson: LessonRevision, evidence: list[EvidenceRow]) -> None:
    print(f"Lesson {_display(lesson.lesson_id, 64)}  revision {lesson.revision}  state {lesson.state}")
    for name in _SHOWN_FIELDS:
        print(f"  {name}: {_display(getattr(lesson, name))}")
    print(f"Evidence ({len(evidence)} events):")
    for row in evidence:
        if not row.present:
            print(f"  {_display(row.event_id, 64)}  missing")
            continue
        print(
            f"  {_display(row.event_id, 64)}  {_display(row.phase, 16)}  {_display(row.op, 16)}  "
            f"{_display(row.site, 253)}  {_display(row.route, 200)}"
        )


def _emit_list(args: argparse.Namespace, rows: list[LessonRevision]) -> int:
    if getattr(args, "json", False):
        print(json.dumps({"lessons": [dataclasses.asdict(row) for row in rows]}, sort_keys=True, ensure_ascii=False))
    else:
        _print_rows(rows)
    return 0


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #


def _correct(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import corrections

    if not config.enabled:
        _term.emit_error("refused (feature_disabled)")
        return 1
    event = corrections.record_correction(
        store,
        episode_id=str(args.episode),
        text=str(args.text),
        attempt_id=args.attempt,
        excluded_sites=config.excluded_sites,
    )
    lesson = corrections.deterministic_candidate(store, event.event_id, excluded_sites=config.excluded_sites)
    print(f"Recorded correction {event.event_id}.")
    print(f"Candidate lesson {lesson.lesson_id} revision {lesson.revision} ({lesson.state}).")
    print(f"Review it with `hermes-mordred activity candidates show {lesson.lesson_id}`.")
    return 0


def _list_candidates(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    return _emit_list(args, lessons.list_lessons(store, state=_CANDIDATE_STATES))


def _list_lessons(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    return _emit_list(args, lessons.list_lessons(store, state=args.state))


def _show(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    lesson = lessons.get(store, str(args.lesson_id), args.revision)
    evidence = lessons.evidence(store, lesson.lesson_id, lesson.revision)
    if getattr(args, "json", False):
        body = {"lesson": dataclasses.asdict(lesson), "evidence": [dataclasses.asdict(row) for row in evidence]}
        print(json.dumps(body, sort_keys=True, ensure_ascii=False))
    else:
        _print_lesson(lesson, evidence)
    return 0


def _build_one(store: ActivityStore, event_id: str, config: ActivityConfig) -> dict[str, Any]:
    from ..activity import corrections
    from ..activity._gate import ActivityRefused

    try:
        lesson = corrections.deterministic_candidate(store, event_id, excluded_sites=config.excluded_sites)
    except ActivityRefused as exc:
        return {"event_id": event_id, "refused": exc.code}
    return {"event_id": event_id, "lesson_id": lesson.lesson_id, "revision": lesson.revision}


def _build(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity._gate import ActivityRefused, refusal

    if store.episode(str(args.episode)) is None:
        raise ActivityRefused(refusal("episode_unknown"))
    found = [
        event.event_id
        for event in store.events_for_episode(str(args.episode))
        if event.phase == "correction" and args.correction in (None, event.event_id)
    ]
    if not found:
        raise ActivityRefused(refusal("correction_unknown"))
    results = [_build_one(store, event_id, config) for event_id in found]
    if getattr(args, "json", False):
        print(json.dumps({"results": results}, sort_keys=True))
    else:
        for row in results:
            outcome = (
                f"refused ({_display(row['refused'], 64)})"
                if "refused" in row
                else f"candidate {_display(row['lesson_id'], 64)} revision {row['revision']}"
            )
            print(f"  correction {_display(row['event_id'], 64)}: {outcome}")
    return 0 if any("lesson_id" in row for row in results) else 1


def _validate(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    lesson = lessons.validate(store, str(args.lesson_id), args.revision, method=args.method, note=args.note)
    print(f"Validated {lesson.lesson_id} revision {lesson.revision} ({lesson.validation_method}).")
    return 0


def _confirmation(args: argparse.Namespace, lesson: LessonRevision) -> str | None:
    if args.digest is not None:
        return str(args.digest)
    if not _is_tty():
        return None
    print(f"Adopting lesson {_display(lesson.lesson_id, 64)} revision {lesson.revision}")
    print(f"  scope:     {_display(lesson.scope_site)}{_display(lesson.scope_route or '')}")
    print(f"  task:      {_display(lesson.scope_task)}")
    print(f"  guidance:  {_display(lesson.guidance)}")
    print(f"  evidence digest: {lesson.evidence_digest}")
    return _read_line("Type the first 12 characters of the evidence digest to adopt: ")


def _adopt(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    lesson = lessons.get(store, str(args.lesson_id), args.revision)
    typed = _confirmation(args, lesson)
    if typed is None:
        _term.emit_error("adopt needs an interactive terminal, or --digest with the evidence digest")
        return 2
    adopted = lessons.adopt(
        store,
        lesson.lesson_id,
        lesson.revision,
        confirmation=typed,
        now=time.time(),
        excluded_sites=config.excluded_sites,
    )
    print(f"Adopted {adopted.lesson_id} revision {adopted.revision}; it is now retrievable by Hermes sessions.")
    return 0


def _reject(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    lessons.reject(store, str(args.lesson_id), args.revision, reason=args.reason)
    print(f"Rejected {_display(args.lesson_id, 64)} revision {args.revision}.")
    return 0


def _suspend(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    lessons.suspend(store, str(args.lesson_id), args.revision, reason=args.reason)
    print(f"Suspended {_display(args.lesson_id, 64)} revision {args.revision}; retrieval stops immediately.")
    return 0


def _retire(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    lessons.retire(store, str(args.lesson_id), args.revision, reason=args.reason)
    print(f"Retired {_display(args.lesson_id, 64)} revision {args.revision}; retrieval stops immediately.")
    return 0


_REVISE_FIELDS = ("guidance", "applies_when", "does_not_apply", "check_before_use")


def _revise(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    from ..activity import lessons

    changes = {name: getattr(args, name) for name in _REVISE_FIELDS if getattr(args, name) is not None}
    if not changes:
        _term.emit_error("nothing to revise: pass --guidance, --applies-when, --does-not-apply or --check-before-use")
        return 2
    lesson = lessons.revise(store, str(args.lesson_id), args.revision, **changes)
    print(f"New candidate {lesson.lesson_id} revision {lesson.revision}; validate and adopt it to use it.")
    return 0


_TOP: Mapping[str, Callable[[argparse.Namespace], int]] = {
    "correct": _guarded(_correct),
    "validate": _guarded(_validate),
    "adopt": _guarded(_adopt),
    "reject": _guarded(_reject),
}
_CANDIDATES: Mapping[str, Callable[[argparse.Namespace], int]] = {
    "list": _guarded(_list_candidates),
    "show": _guarded(_show),
    "build": _guarded(_build),
}
_LESSONS: Mapping[str, Callable[[argparse.Namespace], int]] = {
    "list": _guarded(_list_lessons),
    "show": _guarded(_show),
    "suspend": _guarded(_suspend),
    "retire": _guarded(_retire),
    "revise": _guarded(_revise),
}
COMMANDS = frozenset({*_TOP, "candidates", "lessons"})


def dispatch(command: str, args: argparse.Namespace) -> int:
    if command == "candidates":
        return _CANDIDATES[str(args.activity_candidates_command)](args)
    if command == "lessons":
        return _LESSONS[str(args.activity_lessons_command)](args)
    return _TOP[command](args)


# --------------------------------------------------------------------------- #
# Parsers (called from ``_cli_parsers._add_activity``)
# --------------------------------------------------------------------------- #


def _lesson_ref(parser: argparse.ArgumentParser, *, revision_required: bool) -> None:
    parser.add_argument("lesson_id", help="Lesson id")
    parser.add_argument("--revision", type=int, required=revision_required, default=None, help="Revision number")


def add_parsers(asub: Any, handler: Callable[[argparse.Namespace], int]) -> None:
    p = asub.add_parser("correct", help="Record an explicit correction of an episode and create a candidate lesson")
    p.add_argument("--episode", required=True, help="Episode id the correction refers to")
    p.add_argument("--text", required=True, help="What should have been done (becomes the lesson's guidance)")
    p.add_argument("--attempt", default=None, help="Attempt id within the episode (default: the latest attempt)")
    p.set_defaults(func=handler)

    for name, text in (("candidates", "Candidate lessons awaiting review"), ("lessons", "Lessons in any state")):
        group = asub.add_parser(name, help=text)
        gsub = group.add_subparsers(dest=f"activity_{name}_command", required=True, metavar="COMMAND")
        p_list = gsub.add_parser("list", help="List lesson revisions (identifiers and states)")
        if name == "lessons":
            p_list.add_argument("--state", default=None, help="Only this state")
        p_list.add_argument("--json", action="store_true", help="Print one JSON object")
        p_list.set_defaults(func=handler)
        p_show = gsub.add_parser("show", help="Show every field of a revision and its evidence identifiers")
        _lesson_ref(p_show, revision_required=False)
        p_show.add_argument("--json", action="store_true", help="Print one JSON object")
        p_show.set_defaults(func=handler)
        if name == "lessons":
            _add_lesson_changes(gsub, handler)
        else:
            _add_candidates_build(gsub, handler)

    p = asub.add_parser("validate", help="Record the independent check a candidate passed")
    _lesson_ref(p, revision_required=True)
    p.add_argument("--method", required=True, choices=["fixture", "readonly_check", "user_confirmed"])
    p.add_argument("--note", default=None, help="Short note (≤ 500 characters)")
    p.set_defaults(func=handler)
    p = asub.add_parser("adopt", help="Adopt a validated revision (asks for its evidence digest)")
    _lesson_ref(p, revision_required=True)
    p.add_argument("--digest", default=None, help="Evidence digest or its first ≥ 12 characters")
    p.set_defaults(func=handler)
    p = asub.add_parser("reject", help="Reject a candidate or validated revision")
    _lesson_ref(p, revision_required=True)
    p.add_argument("--reason", required=True, help="Short reason code, e.g. scope_too_wide")
    p.set_defaults(func=handler)


def _add_candidates_build(gsub: Any, handler: Callable[[argparse.Namespace], int]) -> None:
    p = gsub.add_parser("build", help="Build the deterministic candidate of each correction of an episode")
    p.add_argument("--episode", required=True, help="Episode id")
    p.add_argument("--correction", default=None, help="Only this correction event id")
    p.add_argument("--json", action="store_true", help="Print one JSON object")
    p.set_defaults(func=handler)


def _add_lesson_changes(gsub: Any, handler: Callable[[argparse.Namespace], int]) -> None:
    p = gsub.add_parser("suspend", help="Suspend a revision: retrieval stops immediately")
    _lesson_ref(p, revision_required=True)
    p.add_argument("--reason", required=True, help="Short reason code, e.g. user_contradicted")
    p.set_defaults(func=handler)
    p = gsub.add_parser("retire", help="Retire a revision for good: retrieval stops immediately")
    _lesson_ref(p, revision_required=True)
    p.add_argument("--reason", required=True, help="Short reason code, e.g. workflow_changed")
    p.set_defaults(func=handler)
    p = gsub.add_parser("revise", help="Copy a revision into a new candidate revision with changed text")
    _lesson_ref(p, revision_required=True)
    for option in ("guidance", "applies-when", "does-not-apply", "check-before-use"):
        p.add_argument(f"--{option}", default=None)
    p.set_defaults(func=handler)
