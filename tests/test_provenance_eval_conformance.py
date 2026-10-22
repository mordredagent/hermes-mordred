"""No-model conformance: the real mail collector and the Telegram records against the generated truth.

Measured on 2026-10-22 (this branch): part kind / author / owner-class accuracy
including the rendered head line is 1.000 for every one of the 15 scenario
kinds in both sources, over seeds 0-39 (7,055 mail and 6,667 Telegram parts,
no unpredicted parts). The floors below are those measured numbers: a drop
means the collector or the renderer changed attribution, and the failing
scenario is named in the assertion message.
"""

from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from mordred_hermes.imports.mail import MboxBytes, plan_import
from mordred_hermes.imports.records import OwnerClass, PartKind

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "tools" / "provenance_eval"
SEED = 7
MAIL_FLOOR = 1.0
TELEGRAM_FLOOR = 1.0


def _module(name: str) -> ModuleType:
    """Import ``provenance_eval.<name>`` from ``tools/`` (Hermes ships its own ``tools`` package)."""
    if "provenance_eval" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "provenance_eval", PACKAGE / "__init__.py", submodule_search_locations=[str(PACKAGE)]
        )
        assert spec is not None and spec.loader is not None
        package = importlib.util.module_from_spec(spec)
        sys.modules["provenance_eval"] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"provenance_eval.{name}")


generate_mod = _module("generate")
conformance = _module("conformance")
context_mod = _module("context")
encode_mail = _module("encode_mail")
cli_mod = _module("cli")


@pytest.fixture(scope="module")
def dataset():  # type: ignore[no-untyped-def]
    return generate_mod.generate(SEED)


def test_collector_and_records_match_the_truth_per_scenario(dataset) -> None:  # type: ignore[no-untyped-def]
    report = conformance.run_conformance(dataset)
    rows = report.table()
    assert {(source, scenario) for source, scenario, _ok, _total in rows} == {
        (source, thread.scenario) for source in ("telegram", "mail") for thread in dataset.truth.threads
    }
    failures = [(c.source, c.scenario, c.evidence_id, c.expected, c.actual) for c in report.failures()]
    assert report.accuracy("mail") >= MAIL_FLOOR, failures
    assert report.accuracy("telegram") >= TELEGRAM_FLOOR, failures
    assert report.extras == ()
    assert all(check.head_ok and check.tokens_ok for check in report.checks)


def test_generated_mbox_imports_without_skips_and_keeps_partial_threads(dataset) -> None:  # type: ignore[no-untyped-def]
    truth = dataset.truth
    plan = plan_import(
        [MboxBytes(dataset.mail_mbox)],
        account=truth.account,
        own_addresses=truth.own_addresses,
        sent_label=encode_mail.SENT_LABEL,
        imported_at=1_800_000_000,
    )
    imported = {(part.thread_id, part.message_key) for part in truth.parts if part.source == "mail" and part.imported}
    assert plan.report.parsed == len(imported) > 0
    assert plan.report.skipped == {} and plan.report.conflicts == 0 and plan.report.duplicates == 0
    assert plan.report.html_only > 0 and plan.report.unknown_dates > 0
    assert {thread.conversation.conv_uid for thread in plan.threads} == {
        thread.mail_conv_uid for thread in truth.threads
    }
    partial = {thread.conversation.conv_uid for thread in plan.threads if thread.partial}
    missing_parent = {
        thread.mail_conv_uid
        for thread in truth.threads
        if any(not p.imported for p in truth.parts if p.source == "mail" and p.thread_id == thread.thread_id)
    }
    assert partial == missing_parent


def test_conformance_catches_a_collector_that_credits_the_quoter(dataset) -> None:  # type: ignore[no-untyped-def]
    truth = dataset.truth
    mail = context_mod.mail_threads(truth, dataset.mail_mbox)
    target_thread, target_uid = next(
        (thread_id, part.part_uid)
        for thread_id, thread in mail.items()
        for msg in thread.messages
        for part in msg.parts
        if part.part_kind == PartKind.QUOTED and part.author_owner_class == OwnerClass.ACCOUNT_OWNER
    )

    def credit_quoter(msg):  # type: ignore[no-untyped-def]
        parts = tuple(
            dataclasses.replace(
                part,
                author_id=msg.sender_id,
                author_name=msg.sender_name,
                author_owner_class=msg.owner_class,
            )
            if part.part_uid == target_uid
            else part
            for part in msg.parts
        )
        return dataclasses.replace(msg, parts=parts)

    broken = dict(mail)
    thread = mail[target_thread]
    broken[target_thread] = dataclasses.replace(thread, messages=tuple(credit_quoter(msg) for msg in thread.messages))
    report = conformance.run_conformance(dataset, mail=broken)
    assert [check.evidence_id for check in report.failures()] == [target_uid]
    assert report.accuracy("mail") < 1.0
    assert report.accuracy("telegram") == 1.0


def test_conformance_cli_reports_accuracy(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_mod.main(["conformance", "--seed", str(SEED), "--threads", "15", "--min-accuracy", "1.0"]) == 0
    out = capsys.readouterr().out
    assert "mail: accuracy 1.000" in out and "telegram: accuracy 1.000" in out
    assert "| mail | fullwidth_quote |" in out
