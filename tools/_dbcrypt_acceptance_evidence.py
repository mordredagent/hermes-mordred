"""Offline manifest, provenance, control and phase evidence validation."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import stat
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from _dbcrypt_acceptance_common import (
        _PTH_TEST_INPUTS,
        CONTROL_MARGIN,
        INSTANCES,
        PLATFORM_INSTANCE,
        REQUIRED_COMPONENTS,
        REQUIRED_PROFILES,
        RUN_SCHEMA,
        WINDOWS_PLATFORM_NA,
        WINDOWS_TELEGRAM_MIGRATION_REASON,
        AcceptanceRefused,
        EvidenceAPI,
        Mode,
        _absolute,
        _artifact_ref,
        _evidence_ref,
        _guest_path,
        _hex,
        _input_file,
        _module_functions,
        _normalized_node,
        _object,
        _private_evidence_file,
        _python,
        _relative,
        _require,
        _test_identity,
        _text,
        _timestamp,
        native_operation_bootstrap,
        sha256_file,
    )
else:
    from ._dbcrypt_acceptance_common import (
        _PTH_TEST_INPUTS,
        CONTROL_MARGIN,
        INSTANCES,
        PLATFORM_INSTANCE,
        REQUIRED_COMPONENTS,
        REQUIRED_PROFILES,
        RUN_SCHEMA,
        WINDOWS_PLATFORM_NA,
        WINDOWS_TELEGRAM_MIGRATION_REASON,
        AcceptanceRefused,
        EvidenceAPI,
        Mode,
        _absolute,
        _artifact_ref,
        _evidence_ref,
        _guest_path,
        _hex,
        _input_file,
        _module_functions,
        _normalized_node,
        _object,
        _private_evidence_file,
        _python,
        _relative,
        _require,
        _test_identity,
        _text,
        _timestamp,
        native_operation_bootstrap,
        sha256_file,
    )


def validate_import_provenance(path: Path, *, checkout: Path, environment: Path, mode: Mode) -> None:
    origin = path.resolve(strict=True)
    checkout, environment = checkout.resolve(), environment.resolve()
    if mode == "wheel":
        if origin.is_relative_to(checkout) or not origin.is_relative_to(environment):
            raise AcceptanceRefused("wheel_import_outside_installed_environment")
    elif mode == "source":
        if not origin.is_relative_to(checkout / "src/mordred_hermes"):
            raise AcceptanceRefused("source_import_outside_checkout")
    else:
        raise AcceptanceRefused("unknown_import_mode")


def load_stop_receipt(path: Path) -> dict[str, Any]:
    """Read a frozen final controller receipt; do not invoke AWS or trust a flag.

    This validates the existing controller's receipt shape, not authenticity of
    operator input. Full acceptance additionally needs independent EC2 state
    observations bound to this run (not implemented in this inert slice).
    """
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("not a private regular file")
        if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("permissions")
        payload = path.read_bytes()
        value = json.loads(payload)
        created, deadline, stopped = (value.get(key) for key in ("created", "deadline", "stopped_at"))
        if not all(type(item) in (int, float) and math.isfinite(item) for item in (created, deadline, stopped)):
            raise ValueError("timestamps")
        if not 120 <= deadline - created <= 7200 or stopped < created:
            raise ValueError("timestamps")
        if (
            value.get("version") != 1
            or value.get("instance") not in INSTANCES
            or value.get("state") != "stopped"
            or value.get("start_requested") is not True
            or value.get("start_uncertain") is not False
            or not isinstance(value.get("run"), str)
            or len(value["run"]) != 32
            or any(char not in "0123456789abcdef" for char in value["run"])
            or not isinstance(value.get("account"), str)
            or len(value["account"]) != 12
            or not value["account"].isdecimal()
        ):
            raise ValueError("identity or final state")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise AcceptanceRefused("invalid_independent_stop_receipt") from exc
    return {
        **{key: value[key] for key in ("instance", "run", "created", "deadline", "stopped_at", "state")},
        "sha256": hashlib.sha256(payload).hexdigest(),
        "path": str(path.resolve()),
        "verification": "frozen_controller_record_only",
    }


def _validate_probe(value: Any, *, mode: Mode, checkout: Path, root: Path) -> dict[str, Any]:
    probe = _object(
        value,
        (
            "product_file",
            "interpreter",
            "python_version",
            "platform",
            "versions",
            "driver",
            "token",
            "home_is_temporary",
            "native_provider",
            "native_helper",
            "readiness",
            "maintenance_entrypoint",
        ),
    )
    _require(probe["platform"] in {"linux", "darwin", "win32"} and _text(probe["python_version"]))
    environment = checkout / ".venv" if mode == "source" else root / "wheel-env"
    entrypoint = environment / ("Scripts/hermes-mordred.exe" if probe["platform"] == "win32" else "bin/hermes-mordred")
    _require(probe["maintenance_entrypoint"] == {"path": str(entrypoint), "sha256": sha256_file(entrypoint)})
    interpreter = _absolute(probe["interpreter"])
    _require(interpreter.is_file() and interpreter == _python(environment, probe["platform"]).resolve(strict=True))
    origin = _absolute(probe["product_file"])
    _require(origin.name == "__init__.py" and origin.parent.name == "mordred_hermes")
    validate_import_provenance(origin, checkout=checkout, environment=root / "wheel-env", mode=mode)
    if mode == "wheel":
        _require(origin.parent.parent.name == "site-packages")
    versions = _object(probe["versions"], ("hermes-mordred", "hermes-agent", "sqlcipher3-wheels", "pytest"))
    _require(all(_text(versions[key]) for key in ("hermes-mordred", "hermes-agent", "sqlcipher3-wheels", "pytest")))
    driver = _object(probe["driver"], ("module", "sqlite_version", "cipher_version"))
    _require(all(_text(driver[key]) for key in ("sqlite_version", "cipher_version")))
    _require(_absolute(driver["module"]).is_relative_to(environment) and Path(driver["module"]).is_file())
    token = _object(probe["token"], ("elevated", "uid"))
    _require(type(token["elevated"]) in (bool, type(None)) and (type(token["uid"]) is int or token["uid"] is None))
    _require(probe["home_is_temporary"] is True and probe["native_provider"] is None and probe["native_helper"] is None)
    _require(probe["readiness"] == "not_probed_no_native_collector")
    return probe


def _validate_build_records(value: Any, *, root: Path, checkout: Path, extracted: Path, wheel: Path) -> None:
    _require(isinstance(value, list) and len(value) == 6)
    for row in value:
        record = _object(row, ("argv", "cwd", "started_at", "finished_at", "returncode"))
        _require(
            isinstance(record["argv"], list) and bool(record["argv"]) and all(_text(arg) for arg in record["argv"])
        )
        _require(record["cwd"] == str(root) and type(record["returncode"]) is int and record["returncode"] == 0)
        _require(
            _timestamp(record["started_at"])
            and _timestamp(record["finished_at"])
            and record["finished_at"] >= record["started_at"]
        )
    _require(value[0]["argv"] == ["uv", "build", "--sdist", str(checkout), "--out-dir", str(root / "artifacts")])
    for index, environment in ((1, root / "build-env"), (2, root / "wheel-env")):
        argv = value[index]["argv"]
        _require(len(argv) == 6 and argv[:4] == ["uv", "venv", "--no-project", "--python"])
        _require(argv[-1] == str(environment) and Path(argv[4]).is_absolute())
        _require(Path(argv[4]).resolve(strict=True) == _python(checkout / ".venv").resolve(strict=True))
    _require(
        value[3]["argv"] == ["uv", "pip", "install", "--python", str(_python(root / "build-env")), "hatchling>=1.18"]
    )
    _require(
        value[4]["argv"]
        == [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            str(_python(root / "build-env")),
            str(extracted),
            "--out-dir",
            str(root / "artifacts"),
        ]
    )
    _require(
        value[5]["argv"]
        == [
            "uv",
            "pip",
            "install",
            "--python",
            str(_python(root / "wheel-env")),
            "--link-mode",
            "copy",
            str(wheel) + "[dev,keyvault,extension,dbcrypt,telegram]",
        ]
    )


def _validate_manifest(value: Any, root: Path, *, _api: EvidenceAPI) -> dict[str, Any]:
    manifest = _object(
        value,
        (
            "schema_version",
            "commit",
            "checkout",
            "created_at",
            "sdist",
            "sdist_sha256",
            "wheel",
            "wheel_sha256",
            "extracted_sdist",
            "source_probe",
            "wheel_probe",
            "build_commands",
            "files",
            "native_qualification",
            "native_collectors",
            "missing_native_hooks",
        ),
    )
    _require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1)
    _require(_hex(manifest["commit"], 40) and _timestamp(manifest["created_at"]))
    checkout = _absolute(manifest["checkout"])
    _require(checkout.is_dir() and not root.is_relative_to(checkout))
    files = manifest["files"]
    _require(isinstance(files, dict) and bool(files))
    for name, digest in files.items():
        _relative(name)
        _require(_hex(digest, 64))
    source = _validate_probe(manifest["source_probe"], mode="source", checkout=checkout, root=root)
    wheel_probe = _validate_probe(manifest["wheel_probe"], mode="wheel", checkout=checkout, root=root)
    _require(source["platform"] == wheel_probe["platform"])
    version = source["versions"]["hermes-mordred"]
    _require(version == wheel_probe["versions"]["hermes-mordred"])
    sdist, wheel = (_relative(manifest[key]) for key in ("sdist", "wheel"))
    _require(sdist.as_posix() == f"artifacts/hermes_mordred-{version}.tar.gz")
    _require(
        wheel.parent == Path("artifacts")
        and wheel.name.startswith(f"hermes_mordred-{version}-")
        and wheel.suffix == ".whl"
    )
    for kind, path in (("sdist", sdist), ("wheel", wheel)):
        digest = manifest[kind + "_sha256"]
        _require(_hex(digest, 64) and files.get(path.as_posix()) == digest and sha256_file(root / path) == digest)
    extracted = _relative(manifest["extracted_sdist"])
    _require(extracted.as_posix() == f"extracted-sdist/{sdist.name[:-7]}")
    required = (
        "tests/test_dbcrypt.py",
        "tests/conftest.py",
        "tools/dbcrypt_acceptance.py",
        *_PTH_TEST_INPUTS,
        (extracted / "pyproject.toml").as_posix(),
        Path(wheel_probe["product_file"]).relative_to(root).as_posix(),
    )
    _require(all(name in files for name in required))
    _validate_build_records(
        manifest["build_commands"], root=root, checkout=checkout, extracted=root / extracted, wheel=root / wheel
    )
    _require(manifest["native_qualification"] == "not_run" and manifest["native_collectors"] == "not_integrated")
    _require(
        manifest["missing_native_hooks"]
        == [
            "provision",
            "reopen",
            "verify",
            "independent_ec2_observations",
            "collector_records_across_os_reboot_and_stop_start",
        ]
    )
    if source["platform"] in {"linux", "win32"}:
        _require(
            manifest.get("acceptance_commands")
            == _api.acceptance_commands(checkout=checkout, bundle=root, platform=source["platform"])
        )
    return manifest


def validate_bundle(root: Path, *, _api: EvidenceAPI) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if (root / "src").exists() or (root / "mordred_hermes").exists():
        raise AcceptanceRefused("product_source_on_test_path")
    try:
        manifest = _validate_manifest(json.loads(_input_file(root / "manifest.json").read_text()), root, _api=_api)
        _require(_api._bundle_hashes(root) == manifest["files"])
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise AcceptanceRefused("bundle_hash_mismatch_or_invalid_provenance") from exc
    return manifest


def _owned_copy_directories(parent: Path, copied: Path) -> None:
    current = parent
    for part in (None, *copied.parent.relative_to(parent).parts):
        if part is not None:
            current /= part
        info = current.lstat()
        _require(stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400)
        _require(os.name == "nt" or (info.st_uid == os.getuid() and info.st_mode & 0o077 == 0))


def validate_withdrawable_helper(manifest: Path, *, production: Path, parent: Path) -> dict[str, Any]:
    """Admit only the declared private copy of the actual helper, never create it."""
    try:
        parent, production = _absolute(str(parent)), _absolute(str(production))
        value = _object(
            json.loads(_private_evidence_file(manifest).read_text()),
            ("schema_version", "kind", "path", "sha256", "production_helper_sha256", "identity"),
        )
        _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
        _require(value["kind"] == "dbcrypt_withdrawable_helper")
        copied = _absolute(value["path"])
        _require(copied.is_relative_to(parent) and copied != production and not copied.samefile(production))
        _private_evidence_file(copied)
        _owned_copy_directories(parent, copied)
        _require(os.name == "nt" or bool(copied.stat().st_mode & stat.S_IXUSR))
        _require(copied.suffix.lower() == production.suffix.lower())
        expected = _object(value["identity"], ("device", "inode", "size"))
        _require(
            set(expected) == {"device", "inode", "size"}
            and all(type(item) is int and item >= 0 for item in expected.values())
        )
        info = copied.stat()
        _require(expected == {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size})
        _require(_hex(value["sha256"], 64) and value["sha256"] == value["production_helper_sha256"])
        _require(sha256_file(copied) == value["sha256"] == sha256_file(production))
        retained = copied.with_name(copied.name + ".task15-withdrawn")
        _require(not retained.exists() and not retained.is_symlink())
        return {**value, "manifest_sha256": sha256_file(manifest), "retained_path": str(retained)}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("owned_withdrawable_helper_prerequisite_invalid") from exc


def validate_helper_withdrawal(value: Any) -> dict[str, Any]:
    try:
        row = _object(value, ("kind", "copy", "initial_acquisition", "missing_helper_acquisition", "restored"))
        _require(row["kind"] == "owned_helper_withdrawal")
        copied = row["copy"]
        _require(_hex(copied["sha256"], 64) and copied["sha256"] == copied["production_helper_sha256"])
        _require(_hex(copied["manifest_sha256"], 64) and _text(copied["path"]))
        first, missing = row["initial_acquisition"], row["missing_helper_acquisition"]
        _require(first["returncode"] == 0 and missing["returncode"] == 2)
        for observed, outcome in ((first, "acquired"), (missing, "refused")):
            payload = observed["payload"]
            _require(payload["operation"] == "fresh_unpatched_authority" and payload["outcome"] == outcome)
            _require(payload["bootstrap"] == "direct_unpatched_authority")
            _require(payload["source_before"] == payload["source_after"])
            _require(_hex(payload["source_before"]["record_sha256"], 64))
            _require(_timestamp(observed["started_at"]) and observed["finished_at"] >= observed["started_at"])
        _require(first["payload"]["helper_found"] == copied["path"] and missing["payload"]["helper_found"] is None)
        _require(first["payload"]["source_before"] == missing["payload"]["source_before"])
        _require(first["finished_at"] <= missing["started_at"])
        _require(row["restored"]["sha256"] == copied["sha256"] and row["restored"]["identity"] == copied["identity"])
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("helper_withdrawal_evidence_incomplete") from exc
    return row


def _controller_snapshot(directory: Path, reference: Any, stage: str) -> tuple[dict[str, Any], float]:
    path, row = _evidence_ref(directory, reference)
    _private_evidence_file(path)
    captured = reference["captured_at"]
    _require(_timestamp(captured) and type(row["version"]) is int and row["version"] == 1)
    _require(row["instance"] in INSTANCES and _hex(row["run"], 32))
    _require(
        isinstance(row["account"], str)
        and len(row["account"]) == 12
        and row["account"].isascii()
        and row["account"].isdecimal()
    )
    _require(_timestamp(row["created"]) and _timestamp(row["deadline"]))
    _require(120 <= row["deadline"] - row["created"] <= 7200 and row["created"] <= captured)
    expected_state = "armed" if stage in {"armed", "ready"} else "stopped" if stage == "stopped" else "running"
    _require(row["state"] == expected_state and row["start_requested"] is (expected_state != "armed"))
    if stage != "armed":
        _require(type(row["supervisor_pid"]) is int and row["supervisor_pid"] > 0)
        _require(_timestamp(row["heartbeat"]) and row["created"] <= row["heartbeat"] <= captured)
    if expected_state != "armed":
        _require(row["start_uncertain"] is False)
    if stage == "stopped":
        load_stop_receipt(path)
        _require(row["stopped_at"] <= captured)
    return row, float(captured)


def _same_controller_run(first: dict[str, Any], second: dict[str, Any]) -> None:
    _require(all(first[key] == second[key] for key in ("version", "instance", "run", "account", "created", "deadline")))


def _control_start(
    action: dict[str, Any], directory: Path, armed: dict[str, Any], before: dict[str, Any], mode: str
) -> str | None:
    started, captured = _controller_snapshot(directory, action["started"], "started")
    _same_controller_run(armed, started)
    _require(started["supervisor_pid"] == before["supervisor_pid"] and action["action_at"] <= captured)
    initial = _cloud_observation(directory, action["initial_stopped"])
    running = _cloud_observation(directory, action["running"])
    _require(initial["instance"] == armed["instance"] and initial["controller_run"] == armed["run"])
    _require(initial["state"] == "stopped" and initial["_owner"] is None and initial["_account"] == armed["account"])
    _require(armed["created"] <= initial["observed_at"] <= action["action_at"] <= captured <= running["observed_at"])
    previous_run = None
    if action["operation"] == "stop_start" or action["sequence"] > 1:
        stopped, stopped_capture = _controller_snapshot(directory, action["previous_stop"], "stopped")
        observed = _cloud_observation(directory, action["previous_independent_stop"])
        _require(stopped["instance"] == armed["instance"] and stopped["account"] == armed["account"])
        _require(stopped["run"] != armed["run"] and observed["controller_run"] == stopped["run"])
        _require(
            observed["instance"] == armed["instance"] and observed["state"] == "stopped" and observed["_owner"] is None
        )
        _require(
            observed["_account"] == armed["account"] and stopped_capture <= observed["observed_at"] <= armed["created"]
        )
        previous_run = str(stopped["run"])
    return previous_run


def _control_reboot(action: dict[str, Any], directory: Path, armed: dict[str, Any], mode: str) -> None:
    path, anchor = _evidence_ref(directory, action["start_action"])
    _require(anchor["operation"] in {"start", "stop_start"})
    observation = "provision" if anchor["operation"] == "start" else "ec2_stop_start"
    prior = validate_control_action(path, platform=action["platform"], mode=mode, observation=observation)
    anchor_armed, _captured = _controller_snapshot(path.parent, anchor["armed"], "armed")
    _same_controller_run(armed, anchor_armed)
    _require(prior["sequence"] < action["sequence"] and prior["running_at"] < action["action_at"])
    _require(set(action["modes"]) <= set(prior["modes"]))


def validate_control_action(path: Path, *, platform: str, mode: str, observation: str) -> dict[str, Any]:
    """Validate frozen existing-controller and raw-state evidence; never call AWS."""
    try:
        action = _object(
            json.loads(_private_evidence_file(path).read_text()),
            (
                "schema_version",
                "kind",
                "platform",
                "instance",
                "modes",
                "sequence",
                "operation",
                "action_at",
                "armed",
                "before_action",
                "running",
            ),
        )
        _require(
            type(action["schema_version"]) is int
            and action["schema_version"] == 1
            and action["kind"] == "dbcrypt_control_action"
        )
        _require(action["platform"] == platform and action["instance"] == PLATFORM_INSTANCE[platform])
        _require(
            action["operation"]
            == {
                "provision": "start",
                "process_restart": "start",
                "os_reboot": "reboot",
                "ec2_stop_start": "stop_start",
            }[observation]
        )
        _require(
            isinstance(action["modes"], list)
            and mode in action["modes"]
            and action["modes"] == sorted(set(action["modes"]))
        )
        _require(
            set(action["modes"]) <= {"source", "wheel"} and type(action["sequence"]) is int and action["sequence"] > 0
        )
        _require(_timestamp(action["action_at"]))
        armed, armed_capture = _controller_snapshot(path.parent, action["armed"], "armed")
        stage = "active" if action["operation"] == "reboot" else "ready"
        before, before_capture = _controller_snapshot(path.parent, action["before_action"], stage)
        _same_controller_run(armed, before)
        _require(armed["instance"] == action["instance"])
        _require(armed_capture <= before_capture <= action["action_at"] < armed["deadline"] - CONTROL_MARGIN)
        _require(0 <= action["action_at"] - before["heartbeat"] <= 10)
        previous = None
        if action["operation"] == "reboot":
            _control_reboot(action, path.parent, armed, mode)
        else:
            previous = _control_start(action, path.parent, armed, before, mode)
        running = _cloud_observation(path.parent, action["running"])
        _require(running["instance"] == action["instance"] and running["controller_run"] == armed["run"])
        _require(
            running["state"] == "running"
            and running["_owner"] == armed["run"]
            and running["_account"] == armed["account"]
        )
        _require(action["action_at"] <= running["observed_at"] < armed["deadline"])
        return {
            "platform": platform,
            "instance": action["instance"],
            "controller_run": armed["run"],
            "modes": action["modes"],
            "sequence": action["sequence"],
            "operation": action["operation"],
            "action_at": action["action_at"],
            "running_at": running["observed_at"],
            "created": armed["created"],
            "deadline": armed["deadline"],
            "previous_run": previous,
            "sha256": sha256_file(path),
        }
    except (OSError, ValueError, TypeError, KeyError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("controller_action_incomplete") from exc


def validate_phase_control_binding(phase: dict[str, Any], *, directory: Path) -> dict[str, Any]:
    try:
        path, _record = _evidence_ref(directory, phase["control_action"])
        action = validate_control_action(
            path, platform=phase["platform"], mode=phase["mode"], observation=phase["observation"]
        )
        _require(phase["instance"] == action["instance"] and phase["controller_run"] == action["controller_run"])
        _require(phase["control_sequence"] == action["sequence"])
        _require(
            action["running_at"] <= phase["started_at"] <= phase["finished_at"] < action["deadline"] - CONTROL_MARGIN
        )
    except (OSError, ValueError, TypeError, KeyError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("controller_phase_binding_incomplete") from exc
    return action


def _settled_control_cycle(root: Path, value: Any) -> dict[str, Any]:
    cycle = _object(value, ("action", "stopped", "independent_stopped"))
    path, raw = _evidence_ref(root, cycle["action"])
    observation = {"start": "provision", "reboot": "os_reboot", "stop_start": "ec2_stop_start"}[raw["operation"]]
    _require(isinstance(raw["modes"], list) and bool(raw["modes"]))
    action = validate_control_action(path, platform=raw["platform"], mode=raw["modes"][0], observation=observation)
    armed, _capture = _controller_snapshot(path.parent, raw["armed"], "armed")
    stopped, stopped_capture = _controller_snapshot(root, cycle["stopped"], "stopped")
    _same_controller_run(armed, stopped)
    observed = _cloud_observation(root, cycle["independent_stopped"])
    _require(observed["instance"] == action["instance"] and observed["controller_run"] == action["controller_run"])
    _require(observed["state"] == "stopped" and observed["_owner"] is None and observed["_account"] == armed["account"])
    _require(action["running_at"] <= stopped["stopped_at"] <= stopped_capture <= observed["observed_at"])
    return {
        **action,
        "stopped_at": stopped["stopped_at"],
        "independent_stopped_at": observed["observed_at"],
        "stopped_sha256": cycle["stopped"]["sha256"],
        "independent_stopped_sha256": cycle["independent_stopped"]["sha256"],
        "action_path": path,
        "action_record": raw,
    }


def _ordered_control_cycles(cycles: list[dict[str, Any]]) -> None:
    for platform in {row["platform"] for row in cycles}:
        ordered = sorted((row for row in cycles if row["platform"] == platform), key=lambda row: row["sequence"])
        _require([row["sequence"] for row in ordered] == list(range(1, len(ordered) + 1)))
        _require(ordered[0]["operation"] == "start")
        for before, after in itertools.pairwise(ordered):
            _require(before["action_at"] < after["action_at"])
            if after["operation"] == "reboot":
                _require(
                    before["controller_run"] == after["controller_run"]
                    and before["stopped_sha256"] == after["stopped_sha256"]
                )
            else:
                _require(after["previous_run"] == before["controller_run"])
                record = after["action_record"]
                _require(record["previous_stop"]["sha256"] == before["stopped_sha256"])
                _require(record["previous_independent_stop"]["sha256"] == before["independent_stopped_sha256"])
                _require(before["independent_stopped_at"] <= after["created"])


def validate_control_cycles(root: Path, values: Any, phases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    try:
        _require(isinstance(values, list) and bool(values))
        cycles = [_settled_control_cycle(root, row) for row in values]
        by_hash = {row["sha256"]: row for row in cycles}
        _require(
            len(by_hash) == len(cycles) and set(by_hash) == {phase["control_action"]["sha256"] for phase in phases}
        )
        _ordered_control_cycles(cycles)
        for phase in phases:
            action = by_hash[phase["control_action"]["sha256"]]
            _require(phase["platform"] == action["platform"] and phase["instance"] == action["instance"])
            _require(phase["mode"] in action["modes"] and phase["control_sequence"] == action["sequence"])
            _require(phase["controller_run"] == action["controller_run"])
            _require(action["running_at"] <= phase["started_at"] <= phase["finished_at"] <= action["stopped_at"])
    except (OSError, ValueError, TypeError, KeyError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("controller_cycle_correlation_incomplete") from exc
    return by_hash


def platform_na_reason(
    nodeid: str, reason: str | None = None, *, platform: str = "win32", suite: str = "affected"
) -> str | None:
    identity = _test_identity(nodeid)
    if platform == "linux" and suite == "dbcrypt-activity":
        return (
            "linux_windows_peer_handles"
            if identity == "integration/test_dbcrypt_activity.py::test_windows_peer_swap_refuses"
            and reason in {None, "Windows checked peer source handles"}
            else None
        )
    if platform != "win32" or suite != "affected":
        return None
    if identity.startswith("extension/test_telegram_migrate_store.py::"):
        expected: tuple[str, str] | None = (WINDOWS_TELEGRAM_MIGRATION_REASON, "windows_telegram_migration_module")
    else:
        expected = WINDOWS_PLATFORM_NA.get(_normalized_node(nodeid), WINDOWS_PLATFORM_NA.get(identity))
    if expected is None or (reason is not None and reason != expected[0]):
        return None
    return expected[1]


def _native_node_outcome(node: str, rows: list[dict[str, Any]], platform: str, suite: str) -> str | None:
    _require(all(not row.get("wasxfail") for row in rows))
    actual = {(row["when"], row["outcome"]) for row in rows}
    skipped = [row for row in rows if row["outcome"] == "skipped"]
    if not skipped:
        _require(len(rows) == 3 and actual == {(stage, "passed") for stage in ("setup", "call", "teardown")})
        return None
    _require(len(skipped) == 1)
    reason = platform_na_reason(node, platform=platform, suite=suite)
    _require(reason is not None and skipped[0].get("reason_code") == reason)
    stage = skipped[0]["when"]
    expected = (
        {("setup", "skipped"), ("teardown", "passed")}
        if stage == "setup"
        else {("setup", "passed"), ("call", "skipped"), ("teardown", "passed")}
    )
    _require(stage in {"setup", "call"} and len(rows) == len(expected) and actual == expected)
    return reason


def validate_native_test_report(value: Any, *, platform: str = "", suite: str = "") -> dict[str, Any]:
    try:
        report = _object(value, ("nodeids", "reports", "exitstatus", "collection_errors", "deselected"))
        nodes = report["nodeids"]
        _require(
            isinstance(nodes, list)
            and bool(nodes)
            and all(_text(node) for node in nodes)
            and len(set(nodes)) == len(nodes)
        )
        _require(type(report["exitstatus"]) is int and report["exitstatus"] == 0 and report["collection_errors"] == [])
        _require(isinstance(report["deselected"], list) and all(_text(node) for node in report["deselected"]))
        _require(all(row["nodeid"] in nodes for row in report["reports"]))
        unavailable = []
        for node in nodes:
            reason = _native_node_outcome(
                node, [row for row in report["reports"] if row["nodeid"] == node], platform, suite
            )
            if reason is not None:
                unavailable.append({"nodeid": node, "reason_code": reason})
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("native_test_results_incomplete") from exc
    return {
        **report,
        "platform_na": unavailable,
        "counts": {"passed": len(nodes) - len(unavailable), "platform_na": len(unavailable), "skipped": 0},
    }


def validate_reopen_continuity(before: dict[str, Any], after: dict[str, Any], observation: str) -> None:
    try:
        _require(all(before[key] == after[key] for key in ("mode", "bundle_manifest_sha256", "fixture", "logical")))
        if "native_roots" in before or "native_roots" in after:
            _require(before["native_roots"] == after["native_roots"])
        same_boot = before["boot"]["identity"] == after["boot"]["identity"]
        _require(same_boot if observation == "process_restart" else not same_boot)
        _require(observation in {"process_restart", "os_reboot", "ec2_stop_start"})
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("native_reopen_continuity_failed") from exc


def _validate_exported_import(path: str, *, mode: str, platform: str, bundle: dict[str, Any], bundle_path: str) -> None:
    origin = _guest_path(path, platform)
    checkout, installed = (_guest_path(value, platform) for value in (bundle["checkout"], bundle_path))
    expected = checkout / "src/mordred_hermes" if mode == "source" else installed / "wheel-env"
    _require(origin.is_relative_to(expected) and (mode == "source" or not origin.is_relative_to(checkout)))
    _require(path == bundle[mode + "_probe"]["product_file"])


def _offline_build_records(manifest: dict[str, Any], bundle_path: str) -> None:
    platform = manifest["source_probe"]["platform"]
    root, checkout = (_guest_path(value, platform) for value in (bundle_path, manifest["checkout"]))
    python_name = "Scripts/python.exe" if platform == "win32" else "bin/python"
    source_python = str(checkout / ".venv" / python_name)
    build_python = str(root / "build-env" / python_name)
    wheel_python = str(root / "wheel-env" / python_name)
    rows = manifest["build_commands"]
    _require(isinstance(rows, list) and len(rows) == 6)
    for row in rows:
        _require(row["cwd"] == str(root) and type(row["returncode"]) is int and row["returncode"] == 0)
        _require(
            _timestamp(row["started_at"]) and _timestamp(row["finished_at"]) and row["started_at"] <= row["finished_at"]
        )
    _require(rows[0]["argv"] == ["uv", "build", "--sdist", str(checkout), "--out-dir", str(root / "artifacts")])
    for index, name in ((1, "build-env"), (2, "wheel-env")):
        argv = rows[index]["argv"]
        _require(len(argv) == 6 and argv[:4] == ["uv", "venv", "--no-project", "--python"])
        _require(argv[4] in {source_python, manifest["source_probe"]["interpreter"]} and argv[5] == str(root / name))
    _require(rows[3]["argv"] == ["uv", "pip", "install", "--python", build_python, "hatchling>=1.18"])
    _require(
        rows[4]["argv"]
        == [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            build_python,
            str(root / manifest["extracted_sdist"]),
            "--out-dir",
            str(root / "artifacts"),
        ]
    )
    _require(
        rows[5]["argv"]
        == [
            "uv",
            "pip",
            "install",
            "--python",
            wheel_python,
            "--link-mode",
            "copy",
            str(root / manifest["wheel"]) + "[dev,keyvault,extension,dbcrypt,telegram]",
        ]
    )


def validate_bundle_evidence(value: Any, *, directory: Path) -> dict[str, Any]:
    """Offline closure over exported preparation manifest, artifacts and test inputs."""
    proof = _object(
        value, ("schema_version", "kind", "bundle_path", "manifest", "artifacts", "inputs", "configuration")
    )
    _require(
        type(proof["schema_version"]) is int
        and proof["schema_version"] == 1
        and proof["kind"] == "dbcrypt_bundle_evidence"
    )
    _, manifest = _evidence_ref(directory, proof["manifest"])
    _require(
        type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and _hex(manifest["commit"], 40)
    )
    _offline_build_records(manifest, proof["bundle_path"])
    files = manifest["files"]
    _require(isinstance(files, dict) and bool(files) and all(_hex(digest, 64) for digest in files.values()))
    _require(all(name in files for name in _PTH_TEST_INPUTS))
    required = {name for name in files if name.startswith(("tests/", "tools/")) or name in _PTH_TEST_INPUTS}
    _require(bool(required) and set(proof["inputs"]) == required)
    inputs = {}
    for name in sorted(required):
        _relative(name)
        path = _artifact_ref(directory, proof["inputs"][name])
        _require(sha256_file(path) == files[name])
        inputs[name] = path
    for kind in ("sdist", "wheel"):
        artifact = _artifact_ref(directory, proof["artifacts"][kind])
        _require(sha256_file(artifact) == manifest[kind + "_sha256"] == files[manifest[kind]])
    captured = {name for name in files if name.startswith("artifacts/native-build/")}
    _require(set(proof.get("native_build", {})) == captured)
    for name in captured:
        _require(sha256_file(_artifact_ref(directory, proof["native_build"][name])) == files[name])
    config_name = manifest["extracted_sdist"] + "/pyproject.toml"
    configuration = _artifact_ref(directory, proof["configuration"])
    _require(sha256_file(configuration) == files[config_name])
    with tarfile.open(_artifact_ref(directory, proof["artifacts"]["sdist"]), "r:gz") as archive:
        member = archive.getmember(Path(manifest["sdist"]).name.removesuffix(".tar.gz") + "/pyproject.toml")
        _require(member.isfile())
        stream = archive.extractfile(member)
        _require(stream is not None)
        assert stream is not None
        _require(hashlib.sha256(stream.read()).hexdigest() == files[config_name])
    platform = manifest["source_probe"]["platform"]
    _require(platform == manifest["wheel_probe"]["platform"] and platform in {"linux", "win32"})
    for mode in ("source", "wheel"):
        probe = manifest[mode + "_probe"]
        _validate_exported_import(
            probe["product_file"], mode=mode, platform=platform, bundle=manifest, bundle_path=proof["bundle_path"]
        )
        _require(probe["versions"]["hermes-mordred"] == manifest["source_probe"]["versions"]["hermes-mordred"])
        environment = (
            _guest_path(manifest["checkout"], platform) / ".venv"
            if mode == "source"
            else _guest_path(proof["bundle_path"], platform) / "wheel-env"
        )
        _require(_guest_path(probe["driver"]["module"], platform).is_relative_to(environment))
        _require(
            probe["driver"]["cipher_version"] == "4.12.0 community"
            and probe["versions"]["sqlcipher3-wheels"] == "0.5.7"
        )

    return {**manifest, "_inputs": inputs, "_bundle_path": proof["bundle_path"]}


def _phase_bundle(phase: dict[str, Any], directory: Path) -> dict[str, Any]:
    path, proof = _evidence_ref(directory, phase["bundle_evidence"])
    bundle = validate_bundle_evidence(proof, directory=path.parent)
    _require(phase["bundle_manifest_sha256"] == proof["manifest"]["sha256"])
    _require(phase["bundle"] == {key: bundle[key] for key in ("commit", "sdist_sha256", "wheel_sha256")})
    _require(phase["native_implementation_sha256"] == bundle["files"]["tests/_dbcrypt_acceptance_native.py"])
    _require(phase["platform"] == bundle["source_probe"]["platform"])
    return bundle


def _exported_probe(phase: dict[str, Any], execution: dict[str, Any], bundle: dict[str, Any]) -> None:
    probe = execution["import_probe"]
    _require(probe == bundle[phase["mode"] + "_probe"])
    _validate_exported_import(
        probe["product_file"],
        mode=phase["mode"],
        platform=phase["platform"],
        bundle=bundle,
        bundle_path=bundle["_bundle_path"],
    )
    _require(execution["cwd"] == bundle["_bundle_path"] and execution["mode"] == phase["mode"])
    _require(execution["bundle_manifest_sha256"] == phase["bundle_manifest_sha256"])
    _require(phase["platform"] != "win32" or probe["token"]["elevated"] is False)


def _crash_nodes(platform: str) -> set[str]:
    phases = [
        (direction, stage)
        for direction in ("encrypt", "decrypt")
        for stage in ("prepared", "reserved", "verified", "armed", "swapped", "complete", "removed")
    ]
    phases += [("adopt", stage) for stage in ("verified", "armed", "complete")] + [("backup", "published")]
    if platform == "win32":
        phases += [
            (direction, stage) for direction in ("encrypt", "decrypt") for stage in ("retained", "published", "retired")
        ]
    return {
        f"integration/test_dbcrypt_native.py::test_native_crash_subprocess_recovery[{direction}-{stage}]"
        for direction, stage in phases
    }


def _planned_rows(phase: dict[str, Any], bundle: dict[str, Any], *, _api: EvidenceAPI) -> dict[str, dict[str, Any]]:
    from typing import cast

    checkout = cast(Path, _guest_path(bundle["checkout"], phase["platform"]))
    root = cast(Path, _guest_path(bundle["_bundle_path"], phase["platform"]))
    return {
        row["suite"]: row
        for row in _api.native_acceptance_commands(
            checkout=checkout, bundle=root, platform=phase["platform"], kind=phase["acceptance_kind"]
        )
        if row["mode"] == phase["mode"] and "argv" in row
    }


def _selected_nodes(
    phase: dict[str, Any],
    record: dict[str, Any],
    plan: dict[str, Any],
    bundle: dict[str, Any],
    directory: Path,
    *,
    _api: EvidenceAPI,
) -> dict[str, Any]:
    configuration = str(
        _guest_path(bundle["_bundle_path"], phase["platform"]) / bundle["extracted_sdist"] / "pyproject.toml"
    )
    expected_argv = [
        *plan["argv"],
        "--rootdir",
        bundle["_bundle_path"],
        "-c",
        configuration,
        "-p",
        "tests._dbcrypt_acceptance_native",
    ]
    _require(record["argv"] == expected_argv and record["gate_env"] == plan["env"])
    collection = record["collection"]
    _require(
        collection["argv"] == [*expected_argv, "--collect-only"]
        and type(collection["returncode"]) is int
        and collection["returncode"] == 0
    )
    _, collected = _evidence_ref(directory, collection["report"])
    _, report = _evidence_ref(directory, record["pytest_report"])
    _require(collected["exitstatus"] == 0 and collected["reports"] == [] and collected["collection_errors"] == [])
    _require(
        report["nodeids"] == collected["nodeids"] == record["nodeids"]
        and report["deselected"] == collected["deselected"]
    )
    parsed = validate_native_test_report(report, platform=phase["platform"], suite=record["suite"])
    _require(record["counts"] == parsed["counts"] and record["platform_na"] == parsed["platform_na"])
    nodes = {_normalized_node(node) for node in report["nodeids"]}
    modules = {arg.replace("\\", "/").split("/tests/", 1)[-1] for arg in plan["argv"] if arg.endswith(".py")}
    _require({node.split("::", 1)[0] for node in nodes} == modules)
    functions = set().union(*(_module_functions(bundle["_inputs"]["tests/" + module], module) for module in modules))
    if record["suite"] != "windows-vfs":
        _require({node.split("[", 1)[0] for node in nodes} == functions)
    excluded: set[str] = set()
    if record["suite"] == "dbcrypt-native":
        collectors = _module_functions(
            bundle["_inputs"]["tests/integration/test_dbcrypt_collectors.py"], "integration/test_dbcrypt_collectors.py"
        )
        _require(nodes == _crash_nodes(phase["platform"]) | collectors)
    if record["suite"] == "linux-memory":
        _require(
            nodes
            == {
                "integration/test_linux_memory_orchestration_tpm.py::test_real_tpm_orchestration_and_armed_shape_b_backup["
                + entrance
                + "]"
                for entrance in ("setup", "all")
            }
        )
    if record["suite"] == "windows-vfs":
        # AST expansion uses only this reviewed module's literal parametrizations.
        copied = bundle["_inputs"]["tests/integration/test_dbcrypt_windows_vfs.py"]
        checkout = copied.parents[2]
        full = {_normalized_node(node) for node in _api.windows_vfs_required_nodes(checkout, release=False)}
        release = {_normalized_node(node) for node in _api.windows_vfs_required_nodes(checkout, release=True)}
        _require(phase["acceptance_kind"] == "production" and nodes == release)
        excluded = full - release
    _require({_normalized_node(node) for node in report["deselected"]} == excluded)
    return parsed


def _public_read(payload: dict[str, Any], phase: dict[str, Any], bundle: dict[str, Any], *, persistence: bool) -> None:
    _require(
        set(payload["logical"])
        == {profile + ":" + component for profile in REQUIRED_PROFILES for component in REQUIRED_COMPONENTS}
    )
    _require(
        all(_hex(value, 64) for value in payload["logical"].values())
        and set(payload["rows"]) == set(REQUIRED_COMPONENTS)
    )
    _require(payload["fixture"]["root"] == payload["fixture"]["source"]["root"])
    source = payload["fixture"]["source"]
    generation_length = 64 if phase["platform"] == "win32" else 32
    _require(_hex(source["generation"], generation_length) and _hex(source["record_sha256"], 64))
    _require(
        source["provider"] == ("cng" if phase["platform"] == "win32" else "tpm")
        and source["root"]["platform"] == phase["platform"]
    )
    _require(payload["facts"]["filesystem"]["identity"] == source["root"])
    hermes = payload["hermes"]
    _require(
        _hex(hermes["sha256"], 64) and hermes["version"] == bundle[phase["mode"] + "_probe"]["versions"]["hermes-agent"]
    )
    env = (
        _guest_path(bundle["checkout"], phase["platform"]) / ".venv"
        if phase["mode"] == "source"
        else _guest_path(bundle["_bundle_path"], phase["platform"]) / "wheel-env"
    )
    _require(_guest_path(hermes["module"], phase["platform"]).is_relative_to(env))
    if persistence:
        _require(payload["credential_continuity"] == "original_native_protected_reference")
        _require(payload["fixture"] == phase["fixture"] and payload["logical"] == phase["logical"])


def _native_operation_evidence(
    record: dict[str, Any], phase: dict[str, Any], bundle: dict[str, Any], directory: Path
) -> None:
    payload, operation = record["payload"], record["operation"]
    root = _guest_path(record["fixture_path"], phase["platform"])
    filesystem = payload["facts"]["filesystem"]
    scope = filesystem["scope"]
    _require(scope in {"root", "parent"})
    _require(filesystem["observed_path"] == str(root if scope == "root" else root.parent))
    _require(operation == "preflight" or scope == ("parent" if operation == "provision" else "root"))
    if operation != "provision" or phase["acceptance_kind"] != "production":
        return
    probe = bundle[phase["mode"] + "_probe"]
    environment = (
        _guest_path(bundle["checkout"], phase["platform"]) / ".venv"
        if phase["mode"] == "source"
        else _guest_path(bundle["_bundle_path"], phase["platform"]) / "wheel-env"
    )
    path = environment / ("Scripts/hermes-mordred.exe" if phase["platform"] == "win32" else "bin/hermes-mordred")
    entrypoint = probe["maintenance_entrypoint"]
    _require(entrypoint["path"] == str(path) and _hex(entrypoint["sha256"], 64))
    _require(sha256_file(_artifact_ref(directory, record["maintenance_entrypoint_ref"])) == entrypoint["sha256"])
    homes = [root] if root.name.endswith("-crash") else [root, root / "profiles/work", root / "profiles/other"]
    expected = [(str(home), [str(path), "encryption", "enable", "memory"]) for home in homes]
    expected.append((str(root), [str(path), "databases", "encrypt"]))
    ceremonies = payload["ceremonies"]
    _require(isinstance(ceremonies, list) and len(ceremonies) == len(expected))
    previous = record["started_at"]
    for row, (home, argv) in zip(ceremonies, expected, strict=True):
        _require(set(row) == {"home", "argv", "entrypoint_sha256", "started_at", "finished_at", "returncode"})
        _require(row["home"] == home and row["argv"] == argv and row["entrypoint_sha256"] == entrypoint["sha256"])
        _require(type(row["returncode"]) is int and row["returncode"] == 0)
        _require(_timestamp(row["started_at"]) and _timestamp(row["finished_at"]))
        _require(previous <= row["started_at"] <= row["finished_at"] <= record["finished_at"])
        previous = row["finished_at"]


def _native_payload(payload: dict[str, Any], phase: dict[str, Any]) -> None:
    _require(payload["schema_version"] == RUN_SCHEMA and payload["status"] == "executed")
    _require(payload["acceptance_kind"] == phase["acceptance_kind"])
    _require(payload["bootstrap"] == native_operation_bootstrap(phase["acceptance_kind"], payload["operation"]))
    _require(payload["implementation_sha256"] == phase["native_implementation_sha256"])
    facts = payload["facts"]
    _require(
        facts["native_provider"]
        == ("Microsoft Platform Crypto Provider" if phase["platform"] == "win32" else "EC2 NitroTPM")
    )
    _require(_hex(facts["helper"]["sha256"], 64) and _text(facts["helper"]["path"]))
    _require(facts["helper"] == phase["native_facts"]["helper"] and facts["boot"] == phase["boot"])
    if phase["platform"] == "win32":
        _require(
            facts["elevated"] is False
            and type(facts["implementation_flags"]) is int
            and bool(facts["implementation_flags"] & 1)
            and not facts["implementation_flags"] & 2
        )
        _require(facts["filesystem"]["method"] == "checked_confidential_fixed_local_ntfs")
    else:
        _require(
            facts["filesystem"]["method"] == "checked_private_posix" and facts["device"] in {"/dev/tpmrm0", "/dev/tpm0"}
        )
        _require(facts["manufacturer"] == "AMZN" and facts["dmi_vendor"] == "Amazon EC2")


def _collector_arguments(
    record: dict[str, Any], phase: dict[str, Any], bundle: dict[str, Any], directory: Path
) -> None:
    root = _guest_path(bundle["_bundle_path"], phase["platform"])
    environment = (
        _guest_path(bundle["checkout"], phase["platform"]) / ".venv"
        if phase["mode"] == "source"
        else root / "wheel-env"
    )
    python = str(environment / ("Scripts/python.exe" if phase["platform"] == "win32" else "bin/python"))
    helper = root / "tests/_dbcrypt_acceptance_native.py"
    code = f"import runpy; raise SystemExit(runpy.run_path({str(helper)!r})['main']({record['operation']!r}))"
    if phase["acceptance_kind"] == "candidate":
        _require(record["argv"] == [python, "-c", code])
    else:
        argv = record["argv"]
        _require(len(argv) == 3 and argv[0] == python and argv[2] == record["operation"])
        _require(
            _guest_path(argv[1], phase["platform"]).name
            == ("native-collector" if record["operation"] in {"preflight", "provision"} else "hermes")
        )
        expected = (
            f"import sys, runpy; sys.path.insert(0, {str(root)!r}); "
            f"raise SystemExit(runpy.run_path({str(helper)!r})['main'](sys.argv[1]))\n"
        )
        _require(_artifact_ref(directory, record["driver_ref"]).read_text() == expected)


def _provision_fixture_closure(phase: dict[str, Any]) -> None:
    executions, roots = phase["executions"], phase["native_roots"]
    provisioned = {
        row["fixture_path"]: row["payload"]["fixture"] for row in executions if row.get("operation") == "provision"
    }
    _require(set(provisioned) == set(roots.values()))
    _require(len({json.dumps(value["root"], sort_keys=True) for value in provisioned.values()}) == 3)
    for row in executions:
        if row.get("operation") in {"seed", "read"}:
            _require(row["payload"]["fixture"] == provisioned[row["fixture_path"]])


def _native_execution_report(phase: dict[str, Any], directory: Path, *, _api: EvidenceAPI) -> None:
    bundle = _phase_bundle(phase, directory)
    qualified = _api._phase_qualification(phase, directory)
    if phase["platform"] == "win32" and phase["acceptance_kind"] == "candidate":
        _require(qualified is not None)
        assert qualified is not None
        _require(phase["qualified_vfs"] == _api._qualified_vfs_reference(qualified, phase["mode"]))
    executions = phase["executions"]
    _require(isinstance(executions, list) and bool(executions))
    plans = _planned_rows(phase, bundle, _api=_api) if phase["observation"] == "provision" else {}
    suites = [record["suite"] for record in executions if "suite" in record]
    _require(len(suites) == len(set(suites)) and set(suites) == set(plans))
    roots = phase["native_roots"]
    _require(set(roots) == {"persistence", "negative", "crash"} and len(set(roots.values())) == 3)
    for kind, path in roots.items():
        _require(_guest_path(path, phase["platform"]).name == f"mordred-dbcrypt-{phase['mode']}-{kind}")
    operations = []
    for record in executions:
        _require(type(record["returncode"]) is int and record["returncode"] == 0)
        _require(phase["started_at"] <= record["started_at"] <= record["finished_at"] <= phase["finished_at"])
        _exported_probe(phase, record, bundle)
        if "suite" in record:
            _selected_nodes(phase, record, plans[record["suite"]], bundle, directory, _api=_api)
            if record["suite"] == "windows-vfs":
                _require(qualified is not None)
                assert qualified is not None
                actual = qualified[phase["mode"]]
                _require(
                    record["windows_library"]
                    == {"path": actual["dll"], "sha256": actual["dll_sha256"], "kind": actual["target"]}
                )
        else:
            payload = record["payload"]
            _collector_arguments(record, phase, bundle, directory)
            _native_payload(payload, phase)
            _native_operation_evidence(record, phase, bundle, directory)
            _require(record["operation"] == payload["operation"] and record["fixture_path"] in roots.values())
            operations.append((record["operation"], record["fixture_path"]))
            if record["operation"] in {"seed", "read"}:
                _public_read(payload, phase, bundle, persistence=record["fixture_path"] == roots["persistence"])
    expected = [("preflight", roots["persistence"]), ("read", roots["persistence"])]
    if phase["observation"] == "provision":
        expected += [("provision", path) for path in roots.values()] + [
            ("seed", roots[kind]) for kind in ("negative", "persistence")
        ]
    _require(sorted(operations) == sorted(expected))
    _require(executions[0].get("operation") == "preflight" and executions[-1].get("operation") == "read")
    _require(suites == list(plans))
    _require(all(first["finished_at"] <= second["started_at"] for first, second in itertools.pairwise(executions)))
    counts = {
        "passed": sum(row.get("counts", {}).get("passed", 0) for row in executions),
        "collected": sum(len(row.get("nodeids", [])) for row in executions),
        "platform_na": sum(row.get("counts", {}).get("platform_na", 0) for row in executions),
        "failed": 0,
        "skipped": 0,
    }
    _require(phase["test_counts"] == counts and phase["unexpected_skips"] == [])

    if phase["observation"] == "provision":
        _provision_fixture_closure(phase)
    read = next(record["payload"] for record in executions if record.get("operation") == "read")
    _require(read["facts"] == phase["native_facts"] and read["facts"]["boot"] == phase["boot"])


def _native_provision_coverage(phase: dict[str, Any], directory: Path) -> None:
    bundle = _phase_bundle(phase, directory)
    collector = next(row for row in phase["executions"] if row.get("suite") == "dbcrypt-native")
    records = {}
    for reference in collector["collector_rows"]:
        path, payload = _evidence_ref(directory, reference)
        _native_payload(payload, phase)
        _require(path.stem not in records)
        records[path.stem] = payload
    _require(
        set(records)
        == {
            "public-collectors",
            "before-restore",
            "backup-restore",
            "after-restore",
            "restore-finalization-failure",
            "negative",
        }
    )
    for name in ("public-collectors", "before-restore", "after-restore"):
        _require(records[name]["operation"] == "read")
        _public_read(records[name], phase, bundle, persistence=name == "public-collectors")
    before, after = records["before-restore"], records["after-restore"]
    _require(before["logical"] == after["logical"] and before["fixture"] == after["fixture"])
    negative_seed = next(
        row["payload"]
        for row in phase["executions"]
        if row.get("operation") == "seed" and row["fixture_path"] == phase["native_roots"]["negative"]
    )
    _require(before["fixture"] == negative_seed["fixture"] and before["logical"] == negative_seed["logical"])
    restored = records["backup-restore"]
    _require(
        restored["operation"] == "backup_restore"
        and restored["component_generation_before"] != restored["component_generation_after"]
        and restored["backup_retained"] is True
        and restored["guarded_runtime_monitor_backup"] is True
    )
    failure = records["restore-finalization-failure"]
    _require(
        failure["operation"] == "backup_restore_failure"
        and failure["result"] == "restore_incomplete"
        and failure["backup_and_native_key_retained"] is True
    )
    negative = records["negative"]
    required = {
        "held_terminality",
        "unwrap_count",
        "metadata_loss",
        "wrong_key",
        "role_forget",
        "mail_retired_sql_failure_named_retry",
        "fresh_unpatched_native_provider_unavailable",
        "multiprocess_reader_writers",
        "wrong_profile_key",
        "holder_uncertainty_injected",
        "public_encryption_disable",
        "public_encryption_purge",
        "public_keyvault_reset",
        "public_uninstall_helper_guard",
    }
    required |= {
        "broker_helper_guards",
        "cached_access_failure_injected",
        "attach_uri_destinations",
        "wrong_generation",
        "wrong_root_binding",
        "missing_source_no_repair",
        "missing_native_key_observed",
    }
    if phase["platform"] != "win32":
        required.add("public_vault_set-memory-key")
    _require(negative["operation"] == "negative" and required <= set(negative["rows"]))
    _require(negative["initial_unwraps"] == 1 and negative["operation_unwraps"] == 0)
    withdrawal = validate_helper_withdrawal(negative["owned_helper_withdrawal"])
    _require(
        collector["started_at"]
        <= withdrawal["initial_acquisition"]["started_at"]
        <= withdrawal["missing_helper_acquisition"]["finished_at"]
        <= collector["finished_at"]
    )

    _require(withdrawal["copy"]["production_helper_sha256"] == phase["native_facts"]["helper"]["sha256"])
    _require(withdrawal["initial_acquisition"]["payload"]["source_before"] == before["fixture"]["source"])


def _native_phase_coverage(phase: dict[str, Any], directory: Path, *, _api: EvidenceAPI) -> None:
    validate_phase_control_binding(phase, directory=directory)
    _native_execution_report(phase, directory, _api=_api)
    if phase["observation"] == "provision":
        _native_provision_coverage(phase, directory)
    else:
        path, prior = _evidence_ref(directory, phase["provision_reference"])
        _require(prior["observation"] == "provision" and prior["acceptance_kind"] == phase["acceptance_kind"])
        _require(prior["status"] == prior["acceptance_kind"] + "_native_passed")
        _native_phase_coverage(prior, path.parent, _api=_api)
        validate_reopen_continuity(prior, phase, phase["observation"])


def validate_native_phase_evidence(value: Any, *, directory: Path, _api: EvidenceAPI) -> dict[str, Any]:
    try:
        phase = _object(
            value,
            (
                "schema_version",
                "mode",
                "platform",
                "acceptance_kind",
                "bootstrap",
                "observation",
                "executions",
                "fixture",
                "logical",
                "boot",
                "native_implementation_sha256",
            ),
        )
        _require(phase["schema_version"] == RUN_SCHEMA and phase["mode"] in {"source", "wheel"})
        _require(phase.get("status") == "production_native_passed" and phase.get("live_accepted") is False)
        _require(phase["platform"] in {"linux", "win32"} and _hex(phase["native_implementation_sha256"], 64))
        _require(phase["acceptance_kind"] == "production" and phase["bootstrap"] == "automatic_production")
        _require(phase["fixture"]["root"] == phase["fixture"]["source"]["root"])
        _require(_hex(phase["fixture"]["source"]["record_sha256"], 64))
        _native_phase_coverage(phase, directory, _api=_api)
    except (OSError, ValueError, TypeError, KeyError, StopIteration, tarfile.TarError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("native_phase_evidence_incomplete") from exc
    return phase


def _verify_mode_sequences(phases: list[dict[str, Any]]) -> None:
    kinds = ("provision", "process_restart", "os_reboot", "ec2_stop_start")
    for platform in ("linux", "win32"):
        for mode in ("source", "wheel"):
            selected = [row for row in phases if row["platform"] == platform and row["mode"] == mode]
            _require(len(selected) == 4 and {row["observation"] for row in selected} == set(kinds))
            ordered = [next(row for row in selected if row["observation"] == kind) for kind in kinds]
            _require([row["finished_at"] for row in ordered] == sorted(row["finished_at"] for row in ordered))
            baseline = ordered[0]
            for row in ordered[1:]:
                validate_reopen_continuity(baseline, row, row["observation"])
            _require(ordered[2]["boot"]["identity"] != ordered[3]["boot"]["identity"])
            _require(ordered[0]["control_action"]["sha256"] == ordered[1]["control_action"]["sha256"])
            for before, after in itertools.pairwise(ordered[1:]):
                _require(before["finished_at"] < after["_control"]["action_at"])
                _require(before["control_sequence"] < after["control_sequence"])


def _cloud_observation(root: Path, reference: Any) -> dict[str, Any]:
    _, observation = _evidence_ref(root, reference)
    _require(observation["schema"] == 1 and observation["kind"] == "ec2_state_observation")
    _, raw = _evidence_ref(root, observation["raw"])
    rows = [row for reservation in raw["Reservations"] for row in reservation["Instances"]]
    _require(len(rows) == 1 and rows[0]["InstanceId"] == observation["instance"])
    _require(rows[0]["State"]["Name"] == observation["state"] and _timestamp(observation["observed_at"]))
    _require(_hex(observation["controller_run"], 32))
    owners = [tag["Value"] for tag in rows[0].get("Tags", []) if tag.get("Key") == "mordred:dbcrypt-validation"]
    _require(len(owners) <= 1)
    account = raw["Reservations"][0]["OwnerId"]
    return {**observation, "_owner": owners[0] if owners else None, "_account": account}


def _verify_native_stops(root: Path, matrix: dict[str, Any], phases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cycles = validate_control_cycles(root, matrix["control_cycles"], phases)
    _require(len(matrix["stop_receipts"]) == 2)
    receipts = []
    for reference in matrix["stop_receipts"]:
        path, _raw = _evidence_ref(root, reference)
        receipt = load_stop_receipt(path)
        last = max(
            (row for row in cycles.values() if row["instance"] == receipt["instance"]), key=lambda row: row["sequence"]
        )
        _require(receipt["run"] == last["controller_run"] and reference["sha256"] == last["stopped_sha256"])
        _require(
            receipt["stopped_at"] >= max(row["finished_at"] for row in phases if row["instance"] == receipt["instance"])
        )
        receipts.append(receipt)
    _require({row["instance"] for row in receipts} == INSTANCES)
    return receipts


def verify_native_spool(root: Path, *, _api: EvidenceAPI) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": RUN_SCHEMA,
        "phase": "verify",
        "status": "refused",
        "live_accepted": False,
        "reasons": [],
    }
    if not (root / "matrix.json").is_file():
        return {**result, "reasons": ["missing_production_matrix"]}
    try:
        matrix = json.loads(_input_file(root / "matrix.json").read_text())
        _require(matrix["schema_version"] == RUN_SCHEMA)
        phases = []
        for reference in matrix["phases"]:
            path, phase = _evidence_ref(root, reference)
            validated = validate_native_phase_evidence(phase, directory=path.parent, _api=_api)
            action = validate_phase_control_binding(validated, directory=path.parent)
            phases.append({**validated, "_control": action})
        _verify_mode_sequences(phases)
        receipts = _verify_native_stops(root, matrix, phases)
        result.update(
            status="production_native_passed", live_accepted=True, phases=len(phases), owned_instance_receipts=receipts
        )
    except (OSError, ValueError, TypeError, KeyError, StopIteration, tarfile.TarError, AcceptanceRefused):
        result["reasons"] = ["production_matrix_incomplete_or_inconsistent"]
    return result
