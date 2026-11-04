"""Windows package and VFS qualification with inert evidence validation."""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import itertools
import json
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PureWindowsPath
from typing import Any

from _dbcrypt_acceptance_common import (
    _PTH_TEST_INPUTS,
    WINDOWS_RELEASE_SELECTION,
    AcceptanceRefused,
    QualificationAPI,
    WindowsAPI,
    _artifact_ref,
    _evidence_ref,
    _guest_path,
    _hex,
    _input_file,
    _normalized_node,
    _object,
    _relative,
    _require,
    _text,
    _timestamp,
    sha256_file,
)
from _dbcrypt_acceptance_evidence import (
    _validate_exported_import,
    validate_bundle_evidence,
    validate_native_test_report,
)


def windows_vfs_required_nodes(checkout: Path, *, release: bool) -> list[str]:
    """Expand this one reviewed literal-parametrized module without importing it."""
    relative = "tests/integration/test_dbcrypt_windows_vfs.py"
    module = ast.parse((checkout / relative).read_text())
    result: list[str] = []
    excluded = (
        "checkedtest",
        "injected_io",
        "every_creation",
        "inherited_dacl_race",
        "recovery_exclusive_lock",
        "shm_shared_lock",
    )
    for node in module.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        if release and any(token in node.name for token in excluded):
            continue
        dimensions = []
        for decorator in reversed(node.decorator_list):
            if isinstance(decorator, ast.Call) and ast.unparse(decorator.func) == "pytest.mark.parametrize":
                _require(len(decorator.args) == 2 and not decorator.keywords)
                names = ast.literal_eval(decorator.args[0]).split(",")
                ids = []
                for values in ast.literal_eval(decorator.args[1]):
                    row = (values,) if len(names) == 1 else values
                    _require(all(type(value) in (str, int, bool) for value in row))
                    ids.append("-".join(str(value).encode("unicode_escape").decode() for value in row))
                _require(len(ids) == len(set(ids)))
                dimensions.append(ids)
        suffixes = ["-".join(values) for values in itertools.product(*dimensions)] if dimensions else []
        result.extend(f"{relative}::{node.name}[{suffix}]" for suffix in suffixes)
        if not dimensions:
            result.append(f"{relative}::{node.name}")
    _require(bool(result) and len(result) == len(set(result)))
    return result


def _qualification_argv(row: dict[str, Any], action: str, configuration: str) -> None:
    args = row["argv"]
    _require(isinstance(args, list) and args[:3] == ["-q", "-c", configuration])
    _require(args[3:8] == ["-o", "addopts=", "-m", "integration", "--basetemp"])
    _require(_guest_path(args[8], "win32").is_absolute())
    _require(args[9].replace("\\", "/").endswith("tests/integration/test_dbcrypt_windows_vfs.py"))
    _require(args[10:] == (["--collect-only"] if action == "collect" else []))


def _qualification_row(
    directory: Path, reference: Any, target: str, required: list[str], configuration: str
) -> dict[str, Any]:
    links = _object(reference, ("collect", "run"))
    _, collected = _evidence_ref(directory, links["collect"])
    _, run = _evidence_ref(directory, links["run"])
    for action, row in (("collect", collected), ("run", run)):
        _require(row["action"] == action and row["target"] == target and row["nodeids"] == required)
        _require(type(row["collected"]) is int and row["collected"] == len(required))
        _require(
            type(row["pytest_exit_code"]) is int and row["pytest_exit_code"] == 0 and row["collection_errors"] == []
        )
        _qualification_argv(row, action, configuration)
    _require(collected.get("reports", []) == [])
    for key in ("dll_sha256", "driver_native_sha256", "python_sha256"):
        _require(_hex(run[key], 64) and collected[key] == run[key])
    for key in ("dll", "driver_native", "executable", "product_module", "driver_version", "versions"):
        _require(collected[key] == run[key])
    validate_native_test_report({**run, "exitstatus": run["pytest_exit_code"], "deselected": run.get("deselected", [])})
    _require(
        run["driver_version"] == "0.5.7" and run["versions"] == {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"}
    )
    return run


def _qualification_binaries(
    directory: Path, entry: dict[str, Any], row: dict[str, Any], provenance: dict[str, Any]
) -> None:
    for key, digest in (("dll", "dll_sha256"), ("driver_native", "driver_native_sha256"), ("python", "python_sha256")):
        _require(sha256_file(_artifact_ref(directory, entry[key])) == row[digest])
    _artifact_ref(directory, entry["build_stdout"])
    _require(
        sha256_file(_artifact_ref(directory, entry["build_script"]))
        == provenance["source_hashes"]["native/dbcrypt-vfs/build.ps1"]
    )
    args = entry["build_argv"]
    _require(isinstance(args, list) and len(args) == 11 and args[1:4] == ["-NoProfile", "-NonInteractive", "-File"])
    _require(args[5:8] == ["-Target", row["target"], "-OutputDirectory"] and args[9] == "-SqliteIncludeDirectory")
    _require(PureWindowsPath(args[4]).name == "build.ps1")


def _qualification_fixture(directory: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    _, fixture = _evidence_ref(directory, manifest["fixture_verify"])
    _, wrapper = _evidence_ref(directory, manifest["fixture_plan"])
    _, owned = _evidence_ref(directory, manifest["fixture_manifest"])
    plan = wrapper["plan"]
    _require(fixture["schema"] == owned["schema"] == 1 and fixture["ready"] is True and fixture["elevated"] is False)
    _require(
        fixture["sentinel_unchanged"] is True and fixture["direct"]["ok"] is True and fixture["unknown"]["ok"] is True
    )
    _require(_hex(fixture["plan_sha256"], 64) and fixture["plan_sha256"] == wrapper["reviewed_plan_sha256"])
    _require(fixture["sid"] == owned["owner_sid"] == plan["owner_sid"] and _text(fixture["sid"]))
    _require(
        owned["filesystem"] == "exFAT" and all(owned[key] == plan[key] for key in ("non_ntfs_root", "reparse_root"))
    )
    return dict(plan)


def _required_qualification_headers(checkout: Path) -> dict[str, str]:
    import runpy

    return dict(runpy.run_path(str(checkout / "tools/dbcrypt_build_headers.py"))["HEADER_SHA256"])


def _qualification_source(
    directory: Path, manifest: dict[str, Any], checkout: Path, *, _api: QualificationAPI
) -> dict[str, Any]:
    _, provenance = _evidence_ref(directory, manifest["provenance"])
    _, source_map = _evidence_ref(directory, manifest["source_map"])
    _require(_hex(provenance["candidate"], 40) and provenance["candidate"] == source_map["candidate"])
    _require(provenance["source_hashes"] == source_map["files"] and provenance["headers"] == source_map["headers"])
    archive = _artifact_ref(directory, manifest["source_archive"])
    _require(sha256_file(archive) == provenance["source_archive_sha256"])
    with zipfile.ZipFile(archive) as source_zip:
        names = source_zip.namelist()
        _require(len(names) == len(set(names)) and set(names) == set(source_map["delta_files"]))
        for name in names:
            _relative(name)
            _require(
                hashlib.sha256(source_zip.read(name)).hexdigest()
                == source_map["delta_files"][name]
                == source_map["files"][name]
            )

    critical = [
        *(checkout / "native/dbcrypt-vfs").glob("*.c"),
        *(checkout / "native/dbcrypt-vfs").glob("*.h"),
        *(checkout / "src/mordred_hermes/_private_fs").glob("*.py"),
        checkout / "native/dbcrypt-vfs/build.ps1",
        checkout / "pyproject.toml",
        checkout / "src/mordred_hermes/dbcrypt/_windows_vfs.py",
        checkout / "tests/integration/test_dbcrypt_windows_vfs.py",
    ]
    _require(
        all(
            provenance["source_hashes"].get(path.relative_to(checkout).as_posix()) == sha256_file(path)
            for path in critical
        )
    )
    configuration = _artifact_ref(directory, manifest["configuration"])
    _require(
        sha256_file(configuration)
        == provenance["configuration_sha256"]
        == provenance["source_hashes"]["pyproject.toml"]
    )
    _require(PureWindowsPath(provenance["configuration"]) == PureWindowsPath(provenance["source"]) / "pyproject.toml")
    expected_headers = _api._required_qualification_headers(checkout)
    _require(provenance["headers"] == expected_headers and set(manifest["headers"]) == set(expected_headers))
    for name, digest in expected_headers.items():
        _require(sha256_file(_artifact_ref(directory, manifest["headers"][name])) == digest)
    return dict(provenance)


def _qualified_package_artifacts(
    directory: Path, proof: dict[str, Any], bundle: dict[str, Any], row: dict[str, Any], provenance: dict[str, Any]
) -> None:
    wheel_path = _artifact_ref(directory, proof["artifacts"]["wheel"])
    sdist_path = _artifact_ref(directory, proof["artifacts"]["sdist"])
    native_name = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
    critical = {
        name: digest
        for name, digest in provenance["source_hashes"].items()
        if name.startswith(("native/dbcrypt-vfs/", "src/mordred_hermes/_private_fs/"))
        or name == "src/mordred_hermes/dbcrypt/_windows_vfs.py"
    }
    with tarfile.open(sdist_path, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        _require(len(members) == len(archive.getmembers()))
        prefix = Path(bundle["sdist"]).name.removesuffix(".tar.gz")
        for name, digest in critical.items():
            member = members[prefix + "/" + name]
            _require(member.isfile())
            stream = archive.extractfile(member)
            _require(stream is not None)
            assert stream is not None
            _require(hashlib.sha256(stream.read()).hexdigest() == digest)
    with zipfile.ZipFile(wheel_path) as archive:
        _require(len(archive.namelist()) == len(set(archive.namelist())))
        dll = archive.read(native_name)
        _require(hashlib.sha256(dll).hexdigest() == row["dll_sha256"])
        version = bundle["wheel_probe"]["versions"]["hermes-mordred"]
        record = csv.reader(io.StringIO(archive.read(f"hermes_mordred-{version}.dist-info/RECORD").decode()))
        native_entries = [entry for entry in record if entry[0] == native_name]
        encoded = base64.urlsafe_b64encode(hashlib.sha256(dll).digest()).rstrip(b"=").decode()
        _require(len(native_entries) == 1 and native_entries[0][1:] == ["sha256=" + encoded, str(len(dll))])
        for name, digest in critical.items():
            if name.startswith("src/"):
                _require(hashlib.sha256(archive.read(name.removeprefix("src/"))).hexdigest() == digest)
    module = "tests/integration/test_dbcrypt_windows_vfs.py"
    _require(bundle["files"][module] == provenance["source_hashes"][module])


def _qualification_inputs(directory: Path, manifest: dict[str, Any]) -> set[Path]:
    _require(manifest.get("schema") == 2)
    paths = {directory / "manifest.json"}
    diagnostic_path = _artifact_ref(directory, manifest["diagnostic"])
    paths.update(_diagnostic_files(diagnostic_path.parent, json.loads(diagnostic_path.read_text())))
    fixture_path = _artifact_ref(directory, manifest["fixtures"])
    _, fixture_files = _fixture_descriptor(fixture_path)
    paths.update(fixture_files)
    for reference in manifest["results"].values():
        result_path = _artifact_ref(directory, reference)
        value = json.loads(result_path.read_text())
        paths.add(result_path)
        paths.update(_artifact_ref(result_path.parent, value[action]["report"]) for action in ("collect", "run"))
        paths.update(_artifact_ref(result_path.parent, ref) for ref in value["artifacts"].values())
        nested = _artifact_ref(result_path.parent, value["fixtures_descriptor"])
        _require(sha256_file(nested) == sha256_file(fixture_path))
        _, nested_files = _fixture_descriptor(nested)
        paths.update(nested_files)
    proof_path, proof = _evidence_ref(directory, manifest["wheel_bundle"])
    paths.add(proof_path)
    paths.add(_artifact_ref(proof_path.parent, proof["manifest"]))
    paths.add(_artifact_ref(proof_path.parent, proof["configuration"]))
    paths.update(
        _artifact_ref(proof_path.parent, ref)
        for group in ("inputs", "artifacts", "native_build")
        for ref in proof[group].values()
    )
    return paths


def _phase_qualification(phase: dict[str, Any], directory: Path, *, _api: QualificationAPI) -> dict[str, Any] | None:
    if phase["platform"] != "win32":
        _require(phase.get("qualification_evidence") is None)
        return None
    path, _manifest = _evidence_ref(directory, phase["qualification_evidence"])
    # The operator runs offline verification from the accepted source tool.
    # Only read current component bytes; no product import or guest path stat.
    qualified = validate_windows_qualification(path.parent, checkout=Path(__file__).resolve().parents[1], _api=_api)
    if phase["acceptance_kind"] == "production":
        require_production_qualification(qualified)
    _require(qualified["manifest_sha256"] == phase["native_facts"]["qualification_manifest_sha256"])
    observed = qualified["source" if phase["mode"] == "source" else "wheel"]
    _require(observed["dll_sha256"] == phase["native_facts"]["dll"]["sha256"])
    if phase["mode"] == "wheel":
        _require(qualified["wheel"]["bundle_manifest_sha256"] == phase["bundle_manifest_sha256"])
    return qualified


def _native_windows_vfs_rows(rows: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        if row["suite"] == "windows-vfs":
            if kind == "candidate":
                row = {
                    "suite": row["suite"],
                    "mode": row["mode"],
                    "status": "satisfied_by_qualified_artifact_reference",
                }
            elif row["mode"] == "source":
                row = {
                    **row,
                    "library_kind": "packaged Checked",
                    "argv": [*row["argv"][:-1], "-k", WINDOWS_RELEASE_SELECTION, row["argv"][-1]],
                }
        result.append(row)
    return result


def _build_receipt_files(directory: Path, receipt: dict[str, Any]) -> set[Path]:
    files = {directory / "receipt.json"}
    files.update(_artifact_ref(directory, ref) for ref in receipt.get("inputs", {}).values())
    files.update(_artifact_ref(directory, receipt[key]) for key in ("stdout", "stderr", "dll") if key in receipt)
    return files


def _copy_build_receipts(source: Path, target: Path) -> None:
    _require(source.is_absolute() and source == source.resolve(strict=True))
    source = source.resolve(strict=True)
    target.mkdir(mode=0o700, parents=True)
    receipts = sorted(source.glob("*/receipt.json"))
    _require(bool(receipts))
    for path in receipts:
        receipt = json.loads(_input_file(path).read_text())
        for original in _build_receipt_files(path.parent, receipt):
            destination = target / original.relative_to(source)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with destination.open("xb") as output:
                output.write(_input_file(original).read_bytes())


def _validate_build_receipt(
    path: Path,
    *,
    expected_inputs: dict[str, str],
    source_root: str,
    version: str,
    dll_hash: str,
    installed_at: float,
    observed_at: float,
) -> dict[str, Any]:
    receipt = json.loads(_input_file(path).read_text())
    _require(receipt["schema_version"] == 1 and receipt["kind"] == "dbcrypt_vfs_build")
    _require(
        receipt["status"] == "succeeded"
        and receipt["version"] == version
        and type(receipt["returncode"]) is int
        and receipt["returncode"] == 0
    )
    _require(receipt["source_root"] == source_root and _timestamp(receipt["started_at"]))
    _require(receipt["started_at"] <= receipt["finished_at"] <= installed_at <= observed_at)
    args = receipt["argv"]
    _require(
        len(args) == 13
        and args[:6] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
    )
    root = _guest_path(source_root, "win32")
    _require(_guest_path(args[6], "win32") == root / "native/dbcrypt-vfs/build.ps1")
    _require(
        args[7] == "-OutputDirectory" and args[9] == "-SqliteIncludeDirectory" and args[11:] == ["-Target", "Checked"]
    )
    staging = _guest_path(args[8], "win32")
    _require(_guest_path(args[10], "win32") == staging / "include")
    _require(_guest_path(receipt["dll"]["observed_path"], "win32") == staging / "mordred_dbcrypt_checked.dll")
    _require(set(receipt["inputs"]) == set(expected_inputs))
    for name, digest in expected_inputs.items():
        _require(sha256_file(_artifact_ref(path.parent, receipt["inputs"][name])) == digest)
    dll = _artifact_ref(path.parent, receipt["dll"])
    _require(sha256_file(dll) == dll_hash and dll.stat().st_size == receipt["dll"]["size"])
    for key in ("stdout", "stderr"):
        _require(_artifact_ref(path.parent, receipt[key]).stat().st_size == receipt[key]["size"] <= 1024 * 1024)
    return dict(receipt)


def _package_build_inputs(
    bundle: dict[str, Any], directory: Path, proof: dict[str, Any], headers: dict[str, str]
) -> dict[str, str]:
    expected = {}
    with tarfile.open(_artifact_ref(directory, proof["artifacts"]["sdist"]), "r:gz") as archive:
        prefix = Path(bundle["sdist"]).name.removesuffix(".tar.gz") + "/"
        for member in archive.getmembers():
            name = member.name.removeprefix(prefix)
            if name in {"hatch_build.py", "tools/dbcrypt_build_headers.py", "native/dbcrypt-vfs/build.ps1"} or (
                name.startswith("native/dbcrypt-vfs/") and name.endswith((".c", ".h"))
            ):
                stream = archive.extractfile(member)
                _require(member.isfile() and stream is not None)
                assert stream is not None
                expected[name] = hashlib.sha256(stream.read()).hexdigest()
    _require({"hatch_build.py", "tools/dbcrypt_build_headers.py", "native/dbcrypt-vfs/build.ps1"} <= set(expected))
    return {**expected, **{"headers/" + name: digest for name, digest in headers.items()}}


def _local_bundle_proof(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    def ref(name: str) -> dict[str, str]:
        return {"path": name, "sha256": sha256_file(path / name)}

    return {
        "schema_version": 1,
        "kind": "dbcrypt_bundle_evidence",
        "bundle_path": str(path),
        "manifest": ref("manifest.json"),
        "configuration": ref(manifest["extracted_sdist"] + "/pyproject.toml"),
        "artifacts": {kind: ref(manifest[kind]) for kind in ("sdist", "wheel")},
        "inputs": {
            name: ref(name)
            for name in manifest["files"]
            if name.startswith(("tests/", "tools/")) or name in _PTH_TEST_INPUTS
        },
        "native_build": {name: ref(name) for name in manifest["files"] if name.startswith("artifacts/native-build/")},
    }


def matching_build_receipts(
    observed: dict[str, Any], *, bundle: dict[str, Any], proof: dict[str, Any], directory: Path, headers: dict[str, str]
) -> list[str]:
    mode = observed["mode"]
    expected = _package_build_inputs(bundle, directory, proof, headers)
    root = (
        bundle["checkout"]
        if mode == "source"
        else str(_guest_path(proof["bundle_path"], "win32") / bundle["extracted_sdist"])
    )
    matches = []
    for name, reference in proof["native_build"].items():
        if name.startswith("artifacts/native-build/" + mode + "/") and name.endswith("/receipt.json"):
            try:
                _validate_build_receipt(
                    _artifact_ref(directory, reference),
                    expected_inputs=expected,
                    source_root=root,
                    version="editable" if mode == "source" else "standard",
                    dll_hash=observed["dll_sha256"],
                    installed_at=observed["installed_at"],
                    observed_at=observed["observed_at"],
                )
            except (OSError, KeyError, ValueError, TypeError):
                continue
            matches.append(name)
    _require(bool(matches))
    return sorted(matches)


def validate_windows_diagnostic(directory: Path, *, checkout: Path, _api: QualificationAPI) -> dict[str, Any]:
    """Historical full C proof only; never admits native storage eligibility."""
    manifest = json.loads(_input_file(directory / "manifest.json").read_text())
    _require(manifest["schema"] == 1 and manifest["kind"] in {"windows_vfs_diagnostic", "windows_vfs_qualification"})
    provenance = _qualification_source(directory, manifest, checkout, _api=_api)
    full = windows_vfs_required_nodes(checkout, release=False)
    raw = _qualification_row(
        directory, manifest["rows"]["checkedtest_source"], "CheckedTest", full, provenance["configuration"]
    )
    for reference in manifest["rows"]["checkedtest_source"].values():
        _, row = _evidence_ref(directory, reference)
        _require(row.get("deselected", []) == [])
    _qualification_binaries(directory, manifest["artifacts"]["checkedtest_source"], raw, provenance)
    plan = _qualification_fixture(directory, manifest)
    _require(PureWindowsPath(raw["dll"]).parent.parent == PureWindowsPath(plan["test_root"]))
    _require(
        PureWindowsPath(raw["product_module"]).is_relative_to(
            PureWindowsPath(provenance["source"]) / "src/mordred_hermes"
        )
    )
    if "reused_builds" in provenance:
        reused = provenance["reused_builds"]["CheckedTest"]
        critical = {
            key: digest
            for key, digest in provenance["source_hashes"].items()
            if key.startswith(("native/dbcrypt-vfs/", "src/mordred_hermes/_private_fs/"))
            or key == "src/mordred_hermes/dbcrypt/_windows_vfs.py"
        }
        _require(reused["critical_inputs"] == critical and reused["headers"] == provenance["headers"])
        _require(reused["dll_sha256"] == raw["dll_sha256"])
        _require(
            reused["actual_build_stdout_sha256"]
            == manifest["artifacts"]["checkedtest_source"]["build_stdout"]["sha256"]
        )
        _require(reused["cached_runtime"][raw["executable"]] == raw["python_sha256"])
        _require(reused["cached_runtime"][raw["driver_native"]] == raw["driver_native_sha256"])
    return {
        "manifest": manifest,
        "provenance": provenance,
        "diagnostic": {**raw, "role": "diagnostic_source"},
        "manifest_sha256": sha256_file(directory / "manifest.json"),
        "fixture": plan,
    }


def _diagnostic_files(directory: Path, manifest: dict[str, Any]) -> set[Path]:
    paths = {directory / "manifest.json"}
    for key in (
        "provenance",
        "source_map",
        "source_archive",
        "configuration",
        "fixture_plan",
        "fixture_manifest",
        "fixture_verify",
    ):
        paths.add(_artifact_ref(directory, manifest[key]))
    paths.update(_artifact_ref(directory, ref) for ref in manifest["headers"].values())
    for name in ("checkedtest_source", "checked_source"):
        if name in manifest["rows"]:
            paths.update(_artifact_ref(directory, ref) for ref in manifest["rows"][name].values())
            paths.update(
                _artifact_ref(directory, manifest["artifacts"][name][key])
                for key in ("dll", "driver_native", "python", "build_stdout", "build_script")
            )
    return paths


def windows_package_commands(
    *,
    checkout: Path | PureWindowsPath,
    bundle: Path | PureWindowsPath,
    mode: str,
    basetemp: Path | PureWindowsPath,
    configuration: Path | PureWindowsPath,
) -> list[dict[str, Any]]:
    _require(mode in {"source", "wheel"})
    prefix = (
        ["uv", "run", "--project", str(checkout), "python", "-m", "pytest"]
        if mode == "source"
        else [
            "uv",
            "run",
            "--no-project",
            "--python",
            str(bundle / "wheel-env/Scripts/python.exe"),
            "python",
            "-m",
            "pytest",
        ]
    )
    args = [
        "-q",
        "--rootdir",
        str(bundle),
        "-c",
        str(configuration),
        "-o",
        "addopts=",
        "-m",
        "integration",
        "--basetemp",
        str(basetemp),
        str(bundle / "tests/integration/test_dbcrypt_windows_vfs.py"),
        "-k",
        WINDOWS_RELEASE_SELECTION,
        "-p",
        "tests._dbcrypt_acceptance_native",
    ]
    gates = {"MORDRED_DBCRYPT_WINDOWS_VFS_TEST": "1", "MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY": "1"}
    return [
        {
            "argv": [*prefix, *args, *(["--collect-only"] if action == "collect" else [])],
            "pytest_argv": [*args, *(["--collect-only"] if action == "collect" else [])],
            "env": gates,
            "action": action,
        }
        for action in ("collect", "run")
    ]


def canonical_windows_owner_sid(owner: str) -> str:
    """Render RootIdentity's binary SID hex as canonical evidence text (MS-DTYP 2.4.2)."""
    _require(isinstance(owner, str) and 24 <= len(owner) <= 136 and len(owner) % 2 == 0 and _hex(owner, len(owner)))
    sid = bytes.fromhex(owner)
    _require(sid[0] == 1 and 1 <= sid[1] <= 15 and len(sid) == 8 + 4 * sid[1])
    authority = int.from_bytes(sid[2:8], "big")
    authority_text = str(authority) if authority < 2**32 else f"0x{authority:012x}"
    subauthorities = [str(int.from_bytes(sid[offset : offset + 4], "little")) for offset in range(8, len(sid), 4)]
    return "S-1-" + authority_text + "-" + "-".join(subauthorities)


def windows_activation_declaration(source: str) -> bool:
    """Read the frozen loader's literal admission, without executing its code."""
    values = []
    for node in ast.parse(source).body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "NATIVE_QUALIFIED"
        ) or (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "NATIVE_QUALIFIED" for target in node.targets)
        ):
            values.append(node.value)
    _require(len(values) == 1 and isinstance(values[0], ast.Constant) and type(values[0].value) is bool)
    value = values[0]
    assert isinstance(value, ast.Constant)
    return bool(value.value)


def _native_windows_qualification(
    directory: Path, *, checkout: Path, kind: str, _api: QualificationAPI
) -> dict[str, Any]:
    qualified = validate_windows_qualification(directory, checkout=checkout, _api=_api)
    if kind == "production":
        require_production_qualification(qualified)
    return qualified


def require_production_qualification(qualified: dict[str, Any]) -> None:
    """Candidate package eligibility never admits a production Native phase."""
    for mode in ("source", "wheel"):
        _validate_windows_eligibility(qualified[mode]["eligibility"], declared=True)


def _validate_windows_eligibility(value: Any, *, declared: bool) -> None:
    _require(isinstance(value, dict) and set(value) == {"declared_qualified", "observed_qualified", "bootstrap"})
    _require(value["declared_qualified"] is declared and value["observed_qualified"] is True)
    _require(value["bootstrap"] == ("automatic_production" if declared else "explicit_candidate"))


def _validate_package_eligibility(
    observed: dict[str, Any], *, bundle: dict[str, Any], proof: dict[str, Any], directory: Path
) -> None:
    path = _artifact_ref(directory, proof["artifacts"]["sdist"])
    member_name = Path(bundle["sdist"]).name.removesuffix(".tar.gz") + "/src/mordred_hermes/dbcrypt/_windows_vfs.py"
    with tarfile.open(path, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.name == member_name]
        _require(len(members) == 1 and members[0].isfile())
        stream = archive.extractfile(members[0])
        _require(stream is not None)
        assert stream is not None
        declared = windows_activation_declaration(stream.read().decode())
    _validate_windows_eligibility(observed["eligibility"], declared=declared)


def validate_package_observation(
    observed: dict[str, Any],
    *,
    mode: str,
    bundle: dict[str, Any],
    proof: dict[str, Any],
    directory: Path,
    headers: dict[str, str],
) -> None:
    _require(
        mode in {"source", "wheel"}
        and observed["mode"] == mode
        and observed["role"] == "packaged_" + ("editable" if mode == "source" else "wheel")
    )
    _require(
        observed["bundle_manifest_sha256"] == proof["manifest"]["sha256"] and observed["commit"] == bundle["commit"]
    )
    _require(
        observed["elevated"] is False
        and observed["env_dll_override"] is None
        and observed["test_exports_absent"] is True
    )
    _validate_package_eligibility(observed, bundle=bundle, proof=proof, directory=directory)
    _validate_exported_import(
        observed["product_module"], mode=mode, platform="win32", bundle=bundle, bundle_path=proof["bundle_path"]
    )
    env = (
        _guest_path(bundle["checkout"], "win32") / ".venv"
        if mode == "source"
        else _guest_path(proof["bundle_path"], "win32") / "wheel-env"
    )
    _require(_guest_path(observed["executable"], "win32") == env / "Scripts/python.exe")
    _require(_guest_path(observed["driver_native"], "win32").is_relative_to(env))
    _require(
        _guest_path(observed["dll"], "win32").is_relative_to(env)
        and _guest_path(observed["record"], "win32").is_relative_to(env)
    )
    _require(
        observed["driver_version"] == "0.5.7"
        and observed["versions"] == {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"}
    )
    _require(observed["filesystem"]["method"] == "checked_confidential_fixed_local_ntfs")
    _require(canonical_windows_owner_sid(observed["filesystem"]["identity"]["owner"]) == observed["sid"])
    expected = _package_build_inputs(bundle, directory, proof, headers)
    root = (
        bundle["checkout"]
        if mode == "source"
        else str(_guest_path(proof["bundle_path"], "win32") / bundle["extracted_sdist"])
    )
    matches = observed["build_receipts"]
    _require(isinstance(matches, list) and bool(matches) and len(matches) == len(set(matches)))
    for name in matches:
        _require(name.startswith("artifacts/native-build/" + mode + "/") and name in proof["native_build"])
        receipt = _validate_build_receipt(
            _artifact_ref(directory, proof["native_build"][name]),
            expected_inputs=expected,
            source_root=root,
            version="editable" if mode == "source" else "standard",
            dll_hash=observed["dll_sha256"],
            installed_at=observed["installed_at"],
            observed_at=observed["observed_at"],
        )
        if mode == "wheel":
            command = bundle["build_commands"][4]
            _require(command["started_at"] <= receipt["started_at"] <= receipt["finished_at"] <= command["finished_at"])
            _require(observed["installed_at"] <= bundle["build_commands"][5]["finished_at"])
        else:
            _require(receipt["finished_at"] <= observed["installed_at"] <= bundle["build_commands"][0]["started_at"])


def _validate_packaged_result(
    directory: Path,
    result: dict[str, Any],
    *,
    mode: str,
    bundle: dict[str, Any],
    proof: dict[str, Any],
    proof_directory: Path,
    diagnostic: dict[str, Any],
    fixtures: dict[str, Any],
) -> dict[str, Any]:
    _require(
        result["schema_version"] == 1
        and result["kind"] == "packaged_windows_vfs_result"
        and result["status"] == "passed"
    )
    _require(result["mode"] == mode and result["diagnostic_manifest_sha256"] == diagnostic["manifest_sha256"])
    _require(result["fixtures_sha256"] == fixtures["manifest_sha256"])
    nested = _artifact_ref(directory, result["fixtures_descriptor"])
    _require(sha256_file(nested) == fixtures["manifest_sha256"])
    _fixture_descriptor(nested)
    paths = {key: _artifact_ref(directory, ref) for key, ref in result["artifacts"].items()}
    required = windows_vfs_required_nodes(Path(__file__).resolve().parents[1], release=True)
    full = windows_vfs_required_nodes(Path(__file__).resolve().parents[1], release=False)
    observations = []
    for index, action in enumerate(("collect", "run")):
        execution = result[action]
        _, report = _evidence_ref(directory, execution["report"])
        obs = report["qualification"]
        _require(obs["fixture_root"] == fixtures["plan"]["test_root"] and obs["sid"] == fixtures["plan"]["owner_sid"])
        validate_package_observation(
            obs,
            mode=mode,
            bundle=bundle,
            proof=proof,
            directory=proof_directory,
            headers=diagnostic["provenance"]["headers"],
        )
        _require(obs["driver_native_sha256"] == diagnostic["diagnostic"]["driver_native_sha256"])
        _require(
            [_normalized_node(node) for node in report["nodeids"]] == [_normalized_node(node) for node in required]
        )
        _require(
            {_normalized_node(node) for node in report["deselected"]}
            == {_normalized_node(node) for node in set(full) - set(required)}
        )
        expected = windows_package_commands(
            checkout=PureWindowsPath(bundle["checkout"]),
            bundle=PureWindowsPath(proof["bundle_path"]),
            mode=mode,
            basetemp=PureWindowsPath(execution["basetemp"]),
            configuration=PureWindowsPath(proof["bundle_path"]) / bundle["extracted_sdist"] / "pyproject.toml",
        )[index]
        _require(execution["argv"] == expected["argv"] and report["pytest_argv"] == expected["pytest_argv"])
        _require(execution["returncode"] == 0 and report["exitstatus"] == 0 and report["collection_errors"] == [])
        _require(execution["started_at"] <= obs["observed_at"] <= execution["finished_at"])
        _require(report["fixture_manifest_sha256"] == fixtures["manifest_sha256"])
        after = report["qualification_after"]
        validate_package_observation(
            after,
            mode=mode,
            bundle=bundle,
            proof=proof,
            directory=proof_directory,
            headers=diagnostic["provenance"]["headers"],
        )
        _require(
            {key: value for key, value in obs.items() if key != "observed_at"}
            == {key: value for key, value in after.items() if key != "observed_at"}
        )
        _require(obs["observed_at"] <= after["observed_at"] <= execution["finished_at"])
        if action == "collect":
            _require(report["reports"] == [])
        else:
            validate_native_test_report(report)
        observations.append(obs)
    _require(result["collect"]["finished_at"] <= result["run"]["started_at"])
    _, collection_report = _evidence_ref(directory, result["collect"]["report"])
    _, run_report = _evidence_ref(directory, result["run"]["report"])
    _require(
        collection_report["nodeids"] == run_report["nodeids"]
        and collection_report["deselected"] == run_report["deselected"]
    )
    before, after = observations
    stable = (
        "mode",
        "role",
        "commit",
        "bundle_manifest_sha256",
        "dll",
        "dll_sha256",
        "driver_native",
        "driver_native_sha256",
        "executable",
        "python_sha256",
        "record",
        "record_sha256",
        "product_module",
        "installed_at",
        "build_receipts",
        "eligibility",
        "filesystem",
        "sid",
    )
    _require(all(before[key] == after[key] for key in stable))
    for key, digest in (
        ("dll", "dll_sha256"),
        ("driver_native", "driver_native_sha256"),
        ("python", "python_sha256"),
        ("record", "record_sha256"),
    ):
        _require(sha256_file(paths[key]) == after[digest])
    _require(after["record_size"] == paths["record"].stat().st_size)
    asset = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
    rows = [row for row in csv.reader(io.StringIO(paths["record"].read_text())) if row[0] == asset]
    encoded = base64.urlsafe_b64encode(bytes.fromhex(after["dll_sha256"])).rstrip(b"=").decode()
    _require(len(rows) == 1 and rows[0][1:] == ["sha256=" + encoded, str(paths["dll"].stat().st_size)])
    if mode == "wheel":
        with zipfile.ZipFile(_artifact_ref(proof_directory, proof["artifacts"]["wheel"])) as wheel:
            _require(hashlib.sha256(wheel.read(asset)).hexdigest() == after["dll_sha256"])
    return {
        **after,
        "nodeids": run_report["nodeids"],
        "target": "Checked",
        "argv": result["run"]["argv"],
        "bundle_manifest_sha256": proof["manifest"]["sha256"],
        "sdist_sha256": bundle["sdist_sha256"],
        "wheel_sha256": bundle["wheel_sha256"],
    }


def _copy_referenced(source: Path, files: set[Path], target: Path) -> None:
    target.mkdir(mode=0o700)
    for original in sorted(files):
        relative = original.relative_to(source)
        _relative(relative.as_posix())
        destination = target / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open("xb") as output:
            output.write(_input_file(original).read_bytes())


def _fixture_descriptor(path: Path) -> tuple[dict[str, Any], set[Path]]:
    value = json.loads(_input_file(path).read_text())
    _require(path.name == "manifest.json" and value["schema"] == 1 and value["kind"] == "windows_vfs_fixtures")
    _qualification_fixture(path.parent, value)
    files = {
        path,
        *(_artifact_ref(path.parent, value[key]) for key in ("fixture_plan", "fixture_manifest", "fixture_verify")),
    }
    return value, files


def qualify_windows_vfs(
    *, bundle: Path, mode: str, diagnostic: Path, fixtures: Path, output: Path, _api: WindowsAPI
) -> Path:
    """One collection and one packaged release run, never custody provisioning."""
    _api._require(_api.sys.platform == "win32" and mode in {"source", "wheel"})
    manifest = _api.validate_bundle(bundle)
    _api.require_native_source_checkout({"mode": mode, "manifest": manifest})
    historical = _api.validate_windows_diagnostic(diagnostic.parent, checkout=Path(manifest["checkout"]))
    fixture, _files = _api._fixture_descriptor(fixtures)
    plan = _api._qualification_fixture(fixtures.parent, fixture)
    _api._require(
        output.is_absolute()
        and output.parent == output.parent.resolve(strict=True)
        and not output.exists()
        and not output.is_relative_to(bundle)
        and not output.is_relative_to(Path(manifest["checkout"]))
    )
    output.mkdir(mode=0o700)
    result: dict[str, Any] = {
        "schema_version": 1,
        "kind": "packaged_windows_vfs_result",
        "status": "failed",
        "mode": mode,
        "diagnostic_manifest_sha256": historical["manifest_sha256"],
        "fixtures_sha256": _api.sha256_file(fixtures),
    }
    _api._copy_referenced(fixtures.parent, _files, output / "fixtures")
    result["fixtures_descriptor"] = {"path": "fixtures/manifest.json", "sha256": _api.sha256_file(fixtures)}
    try:
        configuration = bundle / manifest["extracted_sdist"] / "pyproject.toml"
        rows = _api.windows_package_commands(
            checkout=Path(manifest["checkout"]),
            bundle=bundle,
            mode=mode,
            basetemp=output / "pytest-temp",
            configuration=configuration,
        )
        with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-probe-") as home:
            environment = _api.probe_environment(Path(home))
            environment.update(
                DBCRYPT_BUNDLE=str(bundle),
                MORDRED_DBCRYPT_VFS_DIAGNOSTIC=str(diagnostic),
                MORDRED_DBCRYPT_VFS_FIXTURES_DESCRIPTOR=str(fixtures),
                MORDRED_DBCRYPT_VFS_PACKAGE_MODE=mode,
                MORDRED_DBCRYPT_TEST_ROOT=plan["test_root"],
                MORDRED_DBCRYPT_QUALIFICATION_MANIFEST=str(
                    _api._artifact_ref(fixtures.parent, fixture["fixture_manifest"])
                ),
                UV_NO_SYNC="1",
            )
            for row in rows:
                action = row["action"]
                path = output / (action + ".json")
                started = time.time()
                execution = subprocess.run(  # noqa: S603 - list argv, no shell
                    row["argv"],
                    cwd=bundle,
                    env={**environment, **row["env"], "MORDRED_DBCRYPT_PYTEST_REPORT": str(path)},
                    capture_output=True,
                    timeout=3600,
                    check=False,
                )
                result[action] = {
                    "argv": row["argv"],
                    "basetemp": str(output / "pytest-temp"),
                    "started_at": started,
                    "finished_at": time.time(),
                    "returncode": execution.returncode,
                    "report": {"path": path.name, "sha256": _api.sha256_file(path)},
                }
                _api._require(execution.returncode == 0)
        report = json.loads((output / "run.json").read_text())
        observation = report["qualification_after"]
        result["artifacts"] = {}
        for key, original in (
            ("dll", observation["dll"]),
            ("driver_native", observation["driver_native"]),
            ("python", observation["executable"]),
            ("record", observation["record"]),
        ):
            target = output / (key + ".bin")
            observed_path = Path(original)
            _api._require(
                observed_path.is_absolute()
                and observed_path.resolve(strict=True) == observed_path
                and stat.S_ISREG(observed_path.lstat().st_mode)
            )
            with target.open("xb") as destination:
                destination.write(observed_path.read_bytes())
            result["artifacts"][key] = {"path": target.name, "sha256": _api.sha256_file(target)}
        result["dll_sha256"] = observation["dll_sha256"]
        result["status"] = "passed"
        proof = _api._local_bundle_proof(bundle, manifest)
        _api._validate_packaged_result(
            output,
            result,
            mode=mode,
            bundle=manifest,
            proof=proof,
            proof_directory=bundle,
            diagnostic=historical,
            fixtures={"manifest_sha256": _api.sha256_file(fixtures), "plan": plan},
        )
        _api.validate_bundle(bundle)
        _api.require_native_source_checkout({"mode": mode, "manifest": manifest})
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, AcceptanceRefused):
        result["status"] = "failed"
        _api._write_new(output / "result.json", result)
        raise AcceptanceRefused("packaged_windows_qualification_failed") from None
    _api._write_new(output / "result.json", result)
    return output / "result.json"


def _assemble_windows_qualification(
    *, bundle: Path, diagnostic: Path, source_result: Path, wheel_result: Path, output: Path, _api: WindowsAPI
) -> Path:
    """Offline fixed closure; copies referenced public artifacts only."""
    manifest = _api.validate_bundle(bundle)
    checkout = Path(__file__).resolve().parents[1]
    historical = _api.validate_windows_diagnostic(diagnostic.parent, checkout=checkout)
    _api._require(
        output.is_absolute()
        and output.parent == output.parent.resolve(strict=True)
        and not output.exists()
        and not output.is_relative_to(bundle)
        and not output.is_relative_to(checkout)
    )
    output.mkdir(mode=0o700)
    _api._copy_referenced(
        diagnostic.parent, _api._diagnostic_files(diagnostic.parent, historical["manifest"]), output / "diagnostic"
    )
    # The same original fixture bytes are retained independently of the diagnostic identity.
    # Results bind the operator fixture descriptor's exact bytes; copy it from each producer.
    source_value = json.loads(_api._input_file(source_result).read_text())
    original_fixtures = _api._artifact_ref(source_result.parent, source_value["fixtures_descriptor"])
    fixture, fixture_files = _api._fixture_descriptor(original_fixtures)
    _api._qualification_fixture(original_fixtures.parent, fixture)
    _api._copy_referenced(original_fixtures.parent, fixture_files, output / "fixtures")
    refs = {}
    for mode, path in (("source", source_result), ("wheel", wheel_result)):
        value = json.loads(_api._input_file(path).read_text())
        files = {
            path,
            *(_api._artifact_ref(path.parent, value[action]["report"]) for action in ("collect", "run")),
            *(_api._artifact_ref(path.parent, ref) for ref in value["artifacts"].values()),
        }
        nested = _api._artifact_ref(path.parent, value["fixtures_descriptor"])
        _api._require(_api.sha256_file(nested) == _api.sha256_file(original_fixtures))
        _, nested_files = _api._fixture_descriptor(nested)
        files.update(nested_files)
        _api._copy_referenced(path.parent, files, output / mode)
        copied = output / mode / path.name
        refs[mode] = {"path": copied.relative_to(output).as_posix(), "sha256": _api.sha256_file(copied)}
    export_directory = output / "export"
    export_directory.mkdir(mode=0o700)
    proof = _api._export_bundle_evidence({"bundle": bundle, "manifest": manifest}, export_directory)
    proof_file = output / proof["path"]
    descriptor = {
        "schema": 2,
        "kind": "windows_vfs_qualification",
        "diagnostic": {"path": "diagnostic/manifest.json", "sha256": _api.sha256_file(diagnostic)},
        "fixtures": {"path": "fixtures/manifest.json", "sha256": _api.sha256_file(original_fixtures)},
        "results": refs,
        "wheel_bundle": {"path": proof_file.relative_to(output).as_posix(), "sha256": _api.sha256_file(proof_file)},
    }
    try:
        _api._validate_qualification_payload(output, descriptor, checkout=checkout)
    except AcceptanceRefused:
        _api._write_new(
            output / "assembly-failure.json", {"status": "failed", "reason": "windows_native_qualification_incomplete"}
        )
        raise
    _api._write_new(output / "manifest.json", descriptor)
    return output / "manifest.json"


def assemble_windows_qualification(
    *, bundle: Path, diagnostic: Path, source_result: Path, wheel_result: Path, output: Path, _api: WindowsAPI
) -> Path:
    try:
        return _api._assemble_windows_qualification(
            bundle=bundle, diagnostic=diagnostic, source_result=source_result, wheel_result=wheel_result, output=output
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        tarfile.TarError,
        zipfile.BadZipFile,
        AcceptanceRefused,
    ):
        raise AcceptanceRefused("windows_native_qualification_incomplete") from None


def _validate_qualification_payload(
    directory: Path, manifest: dict[str, Any], *, checkout: Path, _api: QualificationAPI
) -> dict[str, Any]:
    _require(manifest["schema"] == 2 and manifest["kind"] == "windows_vfs_qualification")
    path = _artifact_ref(directory, manifest["diagnostic"])
    historical = validate_windows_diagnostic(path.parent, checkout=checkout, _api=_api)
    fixture_path = _artifact_ref(directory, manifest["fixtures"])
    fixture_manifest = json.loads(fixture_path.read_text())
    plan = _qualification_fixture(fixture_path.parent, fixture_manifest)
    fixture = {"manifest_sha256": sha256_file(fixture_path), "plan": plan}
    proof_path, proof = _evidence_ref(directory, manifest["wheel_bundle"])
    bundle = validate_bundle_evidence(proof, directory=proof_path.parent)
    provenance = historical["provenance"]
    # C/header/private-FS/config/test compatibility; the changed hook is bound by each new receipt.
    _qualified_package_artifacts(
        proof_path.parent,
        proof,
        bundle,
        {"dll_sha256": json.loads(_artifact_ref(directory, manifest["results"]["wheel"]).read_text())["dll_sha256"]},
        provenance,
    )
    released = {}
    for mode in ("source", "wheel"):
        result_path = _artifact_ref(directory, manifest["results"][mode])
        result = json.loads(result_path.read_text())
        released[mode] = _validate_packaged_result(
            result_path.parent,
            result,
            mode=mode,
            bundle=bundle,
            proof=proof,
            proof_directory=proof_path.parent,
            diagnostic=historical,
            fixtures=fixture,
        )
    _require(released["source"]["filesystem"] == released["wheel"]["filesystem"])
    return {
        "diagnostic": historical["diagnostic"],
        "source": released["source"],
        "wheel": released["wheel"],
        "prerequisite": manifest,
        "fixtures": plan,
        "fixture_manifest_sha256": fixture_manifest["fixture_manifest"]["sha256"],
    }


def validate_windows_qualification(directory: Path, *, checkout: Path, _api: QualificationAPI) -> dict[str, Any]:
    try:
        manifest = json.loads(_input_file(directory / "manifest.json").read_text())
        return {
            **_validate_qualification_payload(directory, manifest, checkout=checkout, _api=_api),
            "manifest_sha256": sha256_file(directory / "manifest.json"),
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        tarfile.TarError,
        zipfile.BadZipFile,
        AcceptanceRefused,
    ) as exc:
        raise AcceptanceRefused("windows_native_qualification_incomplete") from exc


def _qualified_vfs_reference(qualified: dict[str, Any], mode: str) -> dict[str, Any]:
    row = qualified[mode]
    return {
        "status": "satisfied_by_qualified_artifact_reference",
        "qualification_manifest_sha256": qualified["manifest_sha256"],
        "mode": mode,
        "dll_sha256": row["dll_sha256"],
        "driver_native_sha256": row["driver_native_sha256"],
        "nodeids": row["nodeids"],
        "original_results": qualified["prerequisite"]["results"],
        "historical_diagnostic": qualified["prerequisite"]["diagnostic"],
    }
