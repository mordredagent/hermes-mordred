"""Failed suite evidence stays bounded and retains the original refusal."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from tests._dbcrypt_support import acceptance_tool

SECRET = "PRIVATE_password_path_and_parameter"


@pytest.fixture
def suite_boundary(tmp_path, monkeypatch):
    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text("{}")
    directory = tmp_path / "evidence/source-provision-files"
    directory.mkdir(parents=True, mode=0o700)
    context = {
        "bundle": bundle,
        "manifest": {"checkout": str(tmp_path), "extracted_sdist": "sdist"},
        "mode": "source",
        "kind": "production",
        "fixtures": {kind: tmp_path / kind for kind in ("persistence", "crash", "negative")},
        "execution_log": [],
    }
    row = {"suite": "affected", "mode": "source", "env": {}, "argv": ["synthetic-pytest"]}
    monkeypatch.setattr(tool, "validate_bundle", lambda *_: None)
    monkeypatch.setattr(tool, "require_native_source_checkout", lambda *_: None)
    monkeypatch.setattr(tool, "probe_interpreter", lambda *_a, **_k: {"product_file": str(tmp_path)})
    monkeypatch.setattr(tool, "validate_import_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(tool, "_native_environment", lambda *_: {})
    monkeypatch.setattr(tool, "_native_driver", lambda *_: tmp_path / "hermes")

    def run_report(raw):
        def process(_context, argv, environment, **kwargs):
            report = Path(environment["MORDRED_DBCRYPT_PYTEST_REPORT"])
            collection = kwargs["name"].endswith("-collection")
            if collection:
                report.write_bytes(b"{}")
                report.chmod(0o600)
            elif raw is not None:
                report.write_bytes(raw)
                report.chmod(0o600)
            record = {
                "argv": argv,
                "name": kwargs["name"],
                "returncode": 0 if collection else 1,
                "status": "process_returned",
            }
            context["execution_log"].append(record)
            return subprocess.CompletedProcess(argv, record["returncode"], SECRET, SECRET), record

        monkeypatch.setattr(tool, "_native_process", process)
        with pytest.raises(tool.AcceptanceRefused, match=r"^native_module_failed:affected$"):
            tool._native_suite(context, row, directory, tmp_path / "baseline.json")
        record = context["execution_log"][-1]
        assert record["returncode"] == 1 and record["status"] == "process_returned"
        assert SECRET not in json.dumps(record)
        return record

    return tool, run_report, directory


def test_failed_suite_keeps_safe_test_hashes_in_original_execution_record(suite_boundary):
    tool, run, _ = suite_boundary
    report = {
        "exitstatus": 1,
        "nodeids": [SECRET],
        "reports": [
            {
                "nodeid": "tests/test_dbcrypt.py::test_open[" + SECRET + "]",
                "when": "call",
                "outcome": "failed",
                "longrepr": SECRET,
            }
        ],
        "collection_errors": [],
    }
    raw = json.dumps(report).encode()
    record = run(raw)
    summary = record["test_failure_summary"]
    assert summary["status"] == "available"
    assert summary["report_bytes"] == len(raw)
    assert summary["report_sha256"] == hashlib.sha256(raw).hexdigest() == record["pytest_report"]["sha256"]
    assert summary["details"] == {
        "hash_scheme": "sha256_canonical_unparameterized_node_base_utf8",
        "exitstatus": 1,
        "finding_count": 1,
        "truncated": False,
        "findings": [
            {
                "module": "tests/test_dbcrypt.py",
                "node_base_sha256": hashlib.sha256(b"tests/test_dbcrypt.py::test_open").hexdigest(),
                "outcome": "failed",
                "when": "call",
            }
        ],
    }
    assert tool.native_test_failure_descriptor(summary)


@pytest.mark.parametrize(
    "raw,status",
    [
        (None, "missing"),
        (b"{bad", "invalid"),
        (b"x" * (8 * 1024 * 1024 + 1), "oversized"),
        (b'{"reports": null}', "invalid"),
    ],
    ids=["missing", "malformed", "oversized", "invalid-shape"],
)
def test_failed_suite_keeps_original_refusal_when_summary_cannot_be_read(suite_boundary, raw, status):
    tool, run, _ = suite_boundary
    record = run(raw)
    summary = record["test_failure_summary"]
    assert summary["status"] == status
    assert summary["details"] is None
    assert tool.native_test_failure_descriptor(summary)
    if status in {"missing", "oversized"}:
        assert summary["report_sha256"] is None and "pytest_report" not in record


def test_report_prioritizes_failure_then_collection_and_caps_findings(suite_boundary):
    _, run, _ = suite_boundary
    report = {
        "exitstatus": 1,
        "reports": [{"nodeid": "tests/test_dbcrypt.py::test_pass", "when": "call", "outcome": "passed"}] * 15000,
        "collection_errors": [{"nodeid": "test_windows_memory_live.py", "outcome": "failed", "message": SECRET}],
    }
    report["reports"] += [
        {"nodeid": "test_dbcrypt.py::test_bad[" + SECRET + "]", "when": "call", "outcome": "failed"}
    ] * 20
    summary = run(json.dumps(report).encode())["test_failure_summary"]
    assert summary["status"] == "available"
    details = summary["details"]
    assert details["finding_count"] == 21 and details["truncated"] is True
    assert len(details["findings"]) == 16
    assert all(row["module"] == "tests/test_dbcrypt.py" and row["outcome"] == "failed" for row in details["findings"])


def test_collection_module_only_windows_path_and_unknown_node_are_sanitized(suite_boundary):
    _, run, _ = suite_boundary
    report = {
        "exitstatus": 2,
        "reports": [],
        "collection_errors": [
            {"nodeid": r"C:\private\tests\test_windows_memory_live.py", "outcome": "failed"},
            {"nodeid": SECRET, "outcome": "failed"},
        ],
    }
    details = run(json.dumps(report).encode())["test_failure_summary"]["details"]
    assert details["findings"] == [
        {
            "module": "tests/test_windows_memory_live.py",
            "node_base_sha256": hashlib.sha256(b"tests/test_windows_memory_live.py").hexdigest(),
            "outcome": "failed",
            "when": "collection",
        },
        {"module": "unrecognized_nodeid", "node_base_sha256": None, "outcome": "failed", "when": "collection"},
    ]


def test_diagnostic_exception_does_not_replace_original_suite_failure(suite_boundary, monkeypatch):
    tool, run, _ = suite_boundary
    monkeypatch.setattr(
        tool, "native_test_failure_summary", lambda *_: (_ for _ in ()).throw(ValueError(SECRET)), raising=False
    )
    record = run(b"{}")
    assert record["test_failure_summary"] == {
        "status": "unavailable",
        "report_bytes": None,
        "report_sha256": None,
        "details": None,
    }


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "mode", "fifo"])
@pytest.mark.skipif(os.name != "posix", reason="POSIX private-file diagnostic boundary")
def test_reader_rejects_special_or_unowned_report_metadata(tmp_path, damage):
    tool = acceptance_tool("dbcrypt_acceptance")
    path = tmp_path / "report.json"
    path.write_bytes(b"{}")
    path.chmod(0o600)
    if damage == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / SECRET)
    elif damage == "hardlink":
        os.link(path, tmp_path / "alias")
    elif damage == "mode":
        path.chmod(0o644)
    else:
        path.unlink()
        os.mkfifo(path, 0o600)
    assert tool.native_test_failure_summary(path) == {
        "status": "unavailable",
        "report_bytes": None,
        "report_sha256": None,
        "details": None,
    }


@pytest.mark.parametrize(
    "damage",
    [
        "extra",
        "size_bool",
        "digest",
        "details_extra",
        "count",
        "truncated",
        "module",
        "hash",
        "outcome",
        "when",
        "available_without_details",
    ],
)
def test_outer_descriptor_contract_rejects_nonclosed_or_inconsistent_fields(damage):
    tool = acceptance_tool("dbcrypt_acceptance")
    summary = {
        "status": "available",
        "report_bytes": 100,
        "report_sha256": "a" * 64,
        "details": {
            "hash_scheme": "sha256_canonical_unparameterized_node_base_utf8",
            "exitstatus": 1,
            "finding_count": 1,
            "truncated": False,
            "findings": [
                {"module": "tests/test_dbcrypt.py", "node_base_sha256": "b" * 64, "outcome": "failed", "when": "call"}
            ],
        },
    }
    assert tool.native_test_failure_descriptor(summary)
    if damage == "extra":
        summary["message"] = SECRET
    elif damage == "size_bool":
        summary["report_bytes"] = True
    elif damage == "digest":
        summary["report_sha256"] = SECRET
    elif damage == "details_extra":
        summary["details"]["raw_nodeid"] = SECRET
    elif damage == "count":
        summary["details"]["finding_count"] = 2
    elif damage == "truncated":
        summary["details"]["truncated"] = True
    elif damage == "available_without_details":
        summary["details"] = None
    else:
        field = {"module": "module", "hash": "node_base_sha256", "outcome": "outcome", "when": "when"}[damage]
        summary["details"]["findings"][0][field] = SECRET
    assert tool.native_test_failure_descriptor(summary) is False


def test_report_row_bound_is_independent_of_byte_bound(suite_boundary):
    tool, run, _ = suite_boundary
    raw = json.dumps({"reports": [{}] * 100001, "collection_errors": []}).encode()
    assert len(raw) < 8 * 1024 * 1024
    summary = run(raw)["test_failure_summary"]
    assert summary["status"] == "invalid" and summary["details"] is None
    assert tool.native_test_failure_descriptor(summary)


def test_module_allowlist_covers_current_cross_platform_suite_selection(tmp_path):
    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    selected = set()
    for platform in ("linux", "win32"):
        for row in tool.native_acceptance_commands(
            checkout=tmp_path, bundle=bundle, platform=platform, kind="production"
        ):
            for arg in row.get("argv", []):
                if str(arg).startswith(str(bundle / "tests")) and str(arg).endswith(".py"):
                    selected.add(Path(arg).relative_to(bundle).as_posix())
    assert selected <= tool.NATIVE_TEST_FAILURE_MODULES
