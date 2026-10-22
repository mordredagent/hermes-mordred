"""Command line: ``generate``, ``conformance``, ``plan``, ``run``, ``compare``.

Run from the repository root as ``uv run python tools/provenance_eval <command>``
(Hermes ships its own top-level ``tools`` package, so ``python -m
tools.provenance_eval`` cannot resolve this directory), or
``PYTHONPATH=tools uv run python -m provenance_eval <command>``.

``run --driver privacy|hermes`` calls real models and requires
``MORDRED_PROVENANCE_EVAL=1``; endpoints, models and keys come from the
environment only (see :mod:`.drivers`). ``--driver fake`` replays a scripted
refusal and needs no gate.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from mordred_hermes.imports.render import HeadStyle

from .conformance import run_conformance
from .generate import DEFAULT_THREADS, generate
from .plan import TIERS, estimate, format_plan
from .run import RunConfig, RunError, compare_runs, format_comparison, run_eval

if TYPE_CHECKING:
    from .drivers import EvalDriver

__all__ = ["REPO_ROOT", "main"]

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_DRIVERS: Final = ("privacy", "hermes", "fake")


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


def _driver(args: argparse.Namespace) -> EvalDriver:
    from .drivers import FakeDriver, HermesDriver, PrivacyLlmDriver, hermes_settings_from_env, privacy_settings_from_env

    if args.driver == "privacy":
        return PrivacyLlmDriver(privacy_settings_from_env())
    if args.driver == "hermes":
        root = Path(args.hermes_home) if args.hermes_home else Path(args.out) / "hermes-home"
        settings = hermes_settings_from_env(
            root.expanduser().resolve(), seed=args.seed, threads=args.threads, style=args.style
        )
        return HermesDriver(settings)
    return FakeDriver()


def _run(args: argparse.Namespace) -> int:
    from .drivers import ENV_GATE

    if args.driver != "fake" and os.environ.get(ENV_GATE) != "1":
        print(f"provenance_eval: model runs require {ENV_GATE}=1; nothing was run.", file=sys.stderr)
        return 2
    config = RunConfig(
        out=Path(args.out),
        tier=args.tier,
        reps=args.reps,
        seed=args.seed,
        style=args.style,
        threads=args.threads,
        max_calls=args.max_calls,
        budget_usd=args.budget_usd,
        usd_per_mtok_in=args.usd_per_mtok_in,
        usd_per_mtok_out=args.usd_per_mtok_out,
        resume=args.resume,
    )
    try:
        summary = run_eval(config, _driver(args))
    except RunError as exc:
        print(f"provenance_eval: {exc.code}; nothing was run.", file=sys.stderr)
        return 2
    print(
        f"{summary.answered}/{summary.planned} answered, {summary.unavailable} unavailable, "
        f"{summary.asked} asked now, {summary.calls} model calls"
        + (f", stopped by {summary.stopped}" if summary.stopped else "")
        + f"; verdict {summary.verdict} -> {summary.out.resolve()}"
    )
    return 0


def _compare(args: argparse.Namespace) -> int:
    try:
        comparison = compare_runs(Path(args.a), Path(args.b))
    except RunError as exc:
        print(f"provenance_eval: {exc.code}", file=sys.stderr)
        return 2
    print(format_comparison(comparison), end="")
    return 0


def _run_parser(commands: Any) -> None:
    run = commands.add_parser("run", help="ask a model driver; resumable JSONL plus report.md / report.json")
    run.add_argument("--driver", choices=_DRIVERS, required=True)
    run.add_argument("--tier", choices=TIERS, default="smoke")
    run.add_argument("--reps", type=int, default=1)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--style", choices=[style.value for style in HeadStyle], default=HeadStyle.PER_PART_EN.value)
    run.add_argument("--out", required=True, help="output directory (outside the repository)")
    run.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    run.add_argument("--max-calls", type=int, default=None, help="hard limit on model calls (whole results file)")
    run.add_argument("--budget-usd", type=float, default=None, help="hard limit; needs both --usd-per-mtok prices")
    run.add_argument("--usd-per-mtok-in", type=float, default=None, help="price per million input tokens")
    run.add_argument("--usd-per-mtok-out", type=float, default=None, help="price per million output tokens")
    run.add_argument("--resume", action="store_true", help="keep answered lines and ask the rest")
    run.add_argument(
        "--hermes-home", default=None, help="throwaway home root for --driver hermes (default <out>/hermes-home)"
    )
    run.set_defaults(handler=_run)
    pair = commands.add_parser("compare", help="paired McNemar test of two runs' results.jsonl")
    pair.add_argument("a")
    pair.add_argument("b")
    pair.set_defaults(handler=_compare)


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
    _run_parser(commands)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return int(args.handler(args))
