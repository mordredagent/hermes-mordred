"""Command line: ``generate``, ``conformance``, ``plan``; ``run`` / ``compare`` arrive with the drivers.

Run from the repository root as ``uv run python tools/provenance_eval <command>``
(Hermes ships its own top-level ``tools`` package, so ``python -m
tools.provenance_eval`` cannot resolve this directory), or
``PYTHONPATH=tools uv run python -m provenance_eval <command>``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from .conformance import run_conformance
from .generate import DEFAULT_THREADS, generate
from .plan import TIERS, estimate, format_plan

__all__ = ["REPO_ROOT", "main"]

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_PR12: Final = "provenance_eval: model drivers land in PR 12; nothing was run."


def _inside_repo(path: Path) -> bool:
    resolved = path.expanduser().resolve()
    return resolved == REPO_ROOT or REPO_ROOT in resolved.parents


def _generate(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if _inside_repo(out):
        print("provenance_eval: refusing to write inside the repository; choose --out outside it.", file=sys.stderr)
        return 2
    dataset = generate(args.seed, n_threads=args.threads)
    out.mkdir(parents=True, exist_ok=True)
    (out / "truth.json").write_text(dataset.truth.to_json(), encoding="utf-8")
    (out / "telegram.json").write_text(dataset.telegram_json(), encoding="utf-8")
    (out / "mail.mbox").write_bytes(dataset.mail_mbox)
    truth = dataset.truth
    print(
        f"seed {truth.seed}: {len(truth.threads)} threads, {len(truth.facts)} facts, "
        f"{len(truth.questions)} questions -> {out.resolve()}"
    )
    return 0


def _conformance(args: argparse.Namespace) -> int:
    report = run_conformance(generate(args.seed, n_threads=args.threads))
    print("| Source | Scenario | Correct | Parts | Accuracy |\n|---|---|---|---|---|")
    for source, scenario, correct, total in report.table():
        print(f"| {source} | {scenario} | {correct} | {total} | {correct / total:.3f} |")
    for source in ("telegram", "mail"):
        print(f"{source}: accuracy {report.accuracy(source):.3f}")
    print(f"overall: accuracy {report.accuracy():.3f}, unpredicted parts {len(report.extras)}")
    if args.verbose:
        for check in report.failures():
            print(f"FAIL {check.source} {check.scenario} {check.evidence_id}: {check.expected} != {check.actual}")
    if args.min_accuracy is not None and report.accuracy() < args.min_accuracy:
        return 1
    return 0


def _plan(args: argparse.Namespace) -> int:
    dataset = generate(args.seed, n_threads=args.threads)
    tiers = TIERS if args.tier == "all" else (args.tier,)
    rows = [row for tier in tiers for row in estimate(dataset, tier, reps=args.reps)]
    print(format_plan(rows))
    return 0


def _stub(_args: argparse.Namespace) -> int:
    print(_PR12, file=sys.stderr)
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provenance_eval", description="Imported-message provenance evaluation")
    commands = parser.add_subparsers(dest="command", required=True)
    gen = commands.add_parser("generate", help="write truth.json, telegram.json and mail.mbox")
    gen.add_argument("--seed", type=int, required=True)
    gen.add_argument("--out", required=True, help="output directory (outside the repository)")
    gen.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    gen.set_defaults(handler=_generate)
    conf = commands.add_parser("conformance", help="no-model importer conformance against the truth")
    conf.add_argument("--seed", type=int, required=True)
    conf.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    conf.add_argument("--min-accuracy", type=float, default=None)
    conf.add_argument("--verbose", action="store_true")
    conf.set_defaults(handler=_conformance)
    plan = commands.add_parser("plan", help="call and token estimates per tier")
    plan.add_argument("--seed", type=int, default=0)
    plan.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    plan.add_argument("--tier", choices=(*TIERS, "all"), default="all")
    plan.add_argument("--reps", type=int, default=3)
    plan.set_defaults(handler=_plan)
    for name in ("run", "compare"):
        commands.add_parser(name, help="model runs (PR 12)").set_defaults(handler=_stub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args, extra = parser.parse_known_args(argv)
    if extra and args.handler is not _stub:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    return int(args.handler(args))
