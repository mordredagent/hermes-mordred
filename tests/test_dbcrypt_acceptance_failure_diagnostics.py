"""Closed failure evidence from real collector boundaries; no native execution."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests._dbcrypt_support import acceptance_tool

SECRET = "private-secret-path-and-password"


@pytest.fixture
def helper():
    return runpy.run_path(str(Path(__file__).with_name("_dbcrypt_acceptance_native.py")))


def refusal(helper, capsys, call):
    helper["main"].__globals__["operation"] = lambda _name: call()
    assert helper["main"]("provision") == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert captured.err == ""
    value = json.loads(captured.out)
    tool = acceptance_tool("dbcrypt_acceptance")
    assert tool.native_refusal_payload(captured.out, "provision", 2) == value
    return value


@pytest.mark.parametrize("seed,stage", [(True, "memory_seed"), (False, "memory_read")])
@pytest.mark.parametrize("code", [2, -9, 3221225477])
def test_memory_child_failure_keeps_exact_code_without_child_output(
    helper, monkeypatch, capsys, tmp_path, seed, stage, code
):
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "candidate")
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=code, stdout=SECRET, stderr=SECRET)
    )
    value = refusal(helper, capsys, lambda: helper["_fresh_memory"](tmp_path, seed=seed))
    assert value["failure"] == {
        "stage": stage,
        "home": "unknown",
        "child_returncode": code,
        "exception_category": "assertion",
    }
    assert value["reason"] == "native_operation_failed"


def test_memory_timeout_does_not_export_partial_output_or_invent_exit_code(helper, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "candidate")

    def timeout(*_a, **_k):
        raise subprocess.TimeoutExpired(SECRET, 180, output=SECRET, stderr=SECRET)

    monkeypatch.setattr(subprocess, "run", timeout)
    value = refusal(helper, capsys, lambda: helper["_fresh_memory"](tmp_path, seed=True))
    assert value["failure"] == {
        "stage": "memory_seed",
        "home": "unknown",
        "child_returncode": None,
        "exception_category": "timeout",
    }


@pytest.mark.parametrize(
    "arguments,stage,reason",
    [
        (["encryption", "enable", "memory"], "memory_enable", "native_memory_enable_failed_retain_root"),
        (["databases", "encrypt"], "database_encrypt", "native_operation_failed"),
    ],
)
def test_checked_maintenance_failure_keeps_reason_and_code(
    helper, monkeypatch, capsys, tmp_path, arguments, stage, reason
):
    executable = Path(sys.prefix) / ("Scripts/hermes-mordred.exe" if sys.platform == "win32" else "bin/hermes-mordred")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "source_probe": {
                    "maintenance_entrypoint": {"path": str(executable), "sha256": helper["_digest"](executable)}
                }
            }
        )
    )
    monkeypatch.setenv("DBCRYPT_BUNDLE", str(tmp_path))
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_MODE", "source")
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=7))
    value = refusal(helper, capsys, lambda: helper["_maintenance"](tmp_path, arguments))
    assert value["reason"] == reason
    assert value["failure"] == {
        "stage": stage,
        "home": "unknown",
        "child_returncode": 7,
        "exception_category": "runtime",
    }


def test_provision_authority_failure_reports_work_after_successful_root(helper, monkeypatch, capsys, tmp_path):
    root = tmp_path / "mordred-dbcrypt-source-persistence"
    observed = []
    globals_ = helper["provision"].__globals__
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "production")
    monkeypatch.setitem(globals_, "_maintenance", lambda home, _args: observed.append(home) or {})
    monkeypatch.setitem(globals_, "_fresh_memory", lambda _home, **_k: {})

    def require_enabled(**_kwargs):
        if len(observed) == 2:
            raise RuntimeError(SECRET)

    monkeypatch.setitem(globals_, "_interfaces", lambda: require_enabled)
    value = refusal(helper, capsys, lambda: helper["provision"](root))
    assert observed == [root, root / "profiles/work"]
    assert value["failure"] == {
        "stage": "memory_authority_check",
        "home": "work",
        "child_returncode": None,
        "exception_category": "runtime",
    }


def test_nested_child_failure_preserves_stage_and_fills_explicit_home(helper, monkeypatch, capsys, tmp_path):
    root = tmp_path / "mordred-dbcrypt-source-persistence"
    globals_ = helper["provision"].__globals__
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "production")
    monkeypatch.setitem(globals_, "_maintenance", lambda *_a: {})
    monkeypatch.setitem(globals_, "_interfaces", lambda: lambda **_k: None)

    def child(_args, **kwargs):
        failed = kwargs["env"]["HERMES_HOME"] == str(root / "profiles/other")
        return SimpleNamespace(returncode=5 if failed else 0, stdout=SECRET if failed else "{}", stderr=SECRET)

    monkeypatch.setattr(subprocess, "run", child)
    value = refusal(helper, capsys, lambda: helper["provision"](root))
    assert value["failure"] == {
        "stage": "memory_seed",
        "home": "other",
        "child_returncode": 5,
        "exception_category": "assertion",
    }


def test_fresh_success_then_decode_failure_keeps_known_zero_and_no_stale_failure(helper, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "candidate")
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=0, stdout=SECRET))
    value = refusal(helper, capsys, lambda: helper["_fresh_memory"](tmp_path, seed=False))
    assert value["failure"]["stage"] == "memory_read"
    assert value["failure"]["child_returncode"] == 0

    def arbitrary():
        raise KeyError(SECRET)

    value = refusal(helper, capsys, arbitrary)
    assert value["failure"] == {
        "stage": "operation",
        "home": "unknown",
        "child_returncode": None,
        "exception_category": "other",
    }


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "stage",
        "home",
        "category",
        "bool",
        "float",
        "negative_overflow",
        "positive_overflow",
        "extra",
        "missing",
        "null",
        "list",
    ],
)
def test_parent_accepts_only_closed_failure_descriptor(damage):
    tool = acceptance_tool("dbcrypt_acceptance")
    diagnostic = {"stage": "memory_read", "home": "work", "child_returncode": 2, "exception_category": "assertion"}
    if damage in {"stage", "home"}:
        diagnostic[damage] = SECRET
    elif damage == "category":
        diagnostic["exception_category"] = SECRET
    elif damage in {"bool", "float", "negative_overflow", "positive_overflow"}:
        diagnostic["child_returncode"] = {
            "bool": True,
            "float": 2.0,
            "negative_overflow": -(2**31) - 1,
            "positive_overflow": 2**32,
        }[damage]
    elif damage == "extra":
        diagnostic["message"] = SECRET
    elif damage == "missing":
        del diagnostic["home"]
    elif damage == "null":
        diagnostic = None
    elif damage == "list":
        diagnostic = []
    value = {
        "schema_version": 2,
        "operation": "provision",
        "status": "refused",
        "reason": "native_operation_failed",
        "failure": diagnostic,
    }
    assert tool.native_refusal_payload(json.dumps(value), "provision", 2) == (value if damage is None else None)


@pytest.mark.parametrize(
    "kind,category",
    [
        (AssertionError, "assertion"),
        (OSError, "os_error"),
        (ValueError, "value"),
        (TypeError, "type"),
        (RuntimeError, "runtime"),
        (type(SECRET, (Exception,), {}), "other"),
    ],
)
def test_exception_category_is_literal_not_message_or_class_name(helper, capsys, kind, category):
    def failed():
        raise kind(SECRET)

    value = refusal(helper, capsys, failed)
    assert value["failure"] == {
        "stage": "operation",
        "home": "unknown",
        "child_returncode": None,
        "exception_category": category,
    }


def test_bad_internal_descriptor_is_not_exported(helper, capsys):
    def failed():
        with helper["_failure_scope"](SECRET, SECRET):
            raise RuntimeError(SECRET)

    value = refusal(helper, capsys, failed)
    assert set(value) == {"schema_version", "operation", "status", "reason"}


def test_real_operation_root_boundary_is_reported_without_importing_native(helper, monkeypatch, capsys):
    monkeypatch.delenv("MORDRED_DBCRYPT_COLLECTORS_TEST", raising=False)
    # Keep actual operation and actual _root; use main directly rather than the
    # convenience helper which replaces operation for isolated child boundaries.
    assert helper["main"]("provision") == 2
    value = json.loads(capsys.readouterr().out)
    assert value["reason"] == "explicit_native_collector_optin_required"
    assert value["failure"] == {
        "stage": "root_validation",
        "home": "unknown",
        "child_returncode": None,
        "exception_category": "runtime",
    }
