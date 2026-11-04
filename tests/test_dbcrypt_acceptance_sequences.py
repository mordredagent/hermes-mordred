"""Real offline validators over synthetic evidence; never native acceptance."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests._dbcrypt_acceptance_evidence import sequence_matrix
from tests._dbcrypt_support import acceptance_tool


def test_complete_synthetic_sequence_and_stop_baseline(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    matrix, phases = sequence_matrix(tool, tmp_path / "spool")
    tool._verify_mode_sequences(phases)
    receipts = tool._verify_native_stops(tmp_path / "spool", matrix, phases)
    assert len(phases) == 16
    assert {row["instance"] for row in receipts} == {"i-095cbe655c196c749", "i-00f4db5c3a204906b"}
    assert {row["stopped_at"] for row in receipts} == {1700.0}


@pytest.mark.parametrize(
    "damage",
    [
        "missing_observation",
        "duplicate_observation",
        "missing_mode",
        "missing_platform",
        "reversed_timestamps",
        "nonincreasing_control",
        "early_action",
        "changed_fixture",
        "changed_logical",
        "changed_bundle",
        "changed_roots",
        "restart_changed_boot",
        "reboot_same_boot",
        "stop_same_boot",
        "reboot_stop_same_boot",
        "changed_start_action",
    ],
)
def test_mode_sequences_refuse_independent_damage(tmp_path: Path, damage: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    _matrix, phases = sequence_matrix(tool, tmp_path / "spool")
    if damage == "missing_observation":
        phases.pop(1)
    elif damage == "duplicate_observation":
        phases.append(copy.deepcopy(phases[1]))
    elif damage == "missing_mode":
        phases = [row for row in phases if row["mode"] != "wheel"]
    elif damage == "missing_platform":
        phases = [row for row in phases if row["platform"] != "win32"]
    elif damage == "reversed_timestamps":
        phases[1]["finished_at"] = 1001.0
    elif damage == "nonincreasing_control":
        phases[2]["control_sequence"] = 1
    elif damage == "early_action":
        phases[2]["_control"]["action_at"] = phases[1]["finished_at"]
    elif damage.startswith("changed_"):
        key = {
            "changed_fixture": "fixture",
            "changed_logical": "logical",
            "changed_bundle": "bundle_manifest_sha256",
            "changed_roots": "native_roots",
            "changed_start_action": "control_action",
        }[damage]
        phases[1][key] = {"sha256": "0" * 64} if key == "control_action" else "changed"
    else:
        target, source = {
            "restart_changed_boot": (1, 2),
            "reboot_same_boot": (2, 0),
            "stop_same_boot": (3, 0),
            "reboot_stop_same_boot": (3, 2),
        }[damage]
        phases[target]["boot"] = phases[source]["boot"]
    with pytest.raises((tool.AcceptanceRefused, ValueError)):
        tool._verify_mode_sequences(phases)


@pytest.mark.parametrize(
    "damage",
    [
        "missing_stop",
        "duplicate_stop",
        "wrong_instance",
        "wrong_run",
        "stale_stop",
        "wrong_digest",
        "tampered_bytes",
    ],
)
def test_native_stops_refuse_independent_damage(tmp_path: Path, damage: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "spool"
    matrix, phases = sequence_matrix(tool, root)
    if damage == "missing_stop":
        matrix["stop_receipts"].pop()
    elif damage == "duplicate_stop":
        matrix["stop_receipts"][1] = matrix["stop_receipts"][0]
    else:
        reference = matrix["stop_receipts"][0]
        path = root / reference["path"]
        value = json.loads(path.read_text())
        if damage == "tampered_bytes":
            path.write_text(path.read_text() + " ")
        elif damage == "stale_stop":
            # Keep the final receipt and settled cycle bound to the same bytes.
            # The real cycle validator must reject a stop before phase completion.
            value["stopped_at"] = 1501.0
            path.write_text(json.dumps(value))
            reference["sha256"] = tool.sha256_file(path)
        elif damage == "wrong_digest":
            alternate = root / "alternate-stop.json"
            alternate.write_text(json.dumps(value, indent=2))
            alternate.chmod(0o600)
            matrix["stop_receipts"][0] = {"path": alternate.name, "sha256": tool.sha256_file(alternate)}
        else:
            key, replacement = {
                "wrong_instance": ("instance", "i-00f4db5c3a204906b"),
                "wrong_run": ("run", "e" * 32),
            }[damage]
            value[key] = replacement
            # A separate validly hashed receipt leaves the real cycle evidence intact.
            alternate = root / "invalid-stop.json"
            alternate.write_text(json.dumps(value))
            alternate.chmod(0o600)
            matrix["stop_receipts"][0] = {"path": alternate.name, "sha256": tool.sha256_file(alternate)}
    with pytest.raises((tool.AcceptanceRefused, ValueError)):
        tool._verify_native_stops(root, matrix, phases)


@pytest.mark.parametrize("damage", ["malformed_json", "tampered_phase", "incomplete_phase"])
def test_malformed_spool_never_claims_live_acceptance(tmp_path: Path, damage: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "spool"
    matrix, phases = sequence_matrix(tool, root)
    path = root / "phase.json"
    path.write_text(json.dumps(phases[0]))
    matrix["phases"] = [{"path": path.name, "sha256": tool.sha256_file(path)}]
    if damage == "tampered_phase":
        path.write_text("{}")
    (root / "matrix.json").write_text("{" if damage == "malformed_json" else json.dumps(matrix))
    result = tool.verify_native_spool(root)
    assert result["status"] == "refused"
    assert result["live_accepted"] is False
    assert result["reasons"] == ["production_matrix_incomplete_or_inconsistent"]


def test_copied_tool_closure_imports_from_unrelated_directory(tmp_path: Path) -> None:
    """The exported collector must load its local facade and all sibling modules."""
    import subprocess
    import sys

    tool = acceptance_tool("dbcrypt_acceptance")
    checkout = Path(__file__).resolve().parents[1]
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    tool._copy_inputs(checkout, bundle)
    for name in ("common", "evidence", "execution", "windows"):
        relative = Path("tools") / f"_dbcrypt_acceptance_{name}.py"
        assert (bundle / relative).is_file()
        assert tool.sha256_file(bundle / relative) == tool.sha256_file(checkout / relative)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    script = """
import importlib.util
from pathlib import Path
import runpy
import sys
path = Path(sys.argv[1]) / 'tools/dbcrypt_acceptance.py'
spec = importlib.util.spec_from_file_location('unrelated.arbitrary_acceptance_alias', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.verify_native_spool(Path(sys.argv[1]))['live_accepted'] is False
assert runpy.run_path(str(path))['AcceptanceRefused'] is module.AcceptanceRefused
collector = runpy.run_path(str(Path(sys.argv[1]) / 'tests/_dbcrypt_acceptance_native.py'))
assert callable(collector['main'])
assert collector['_tool']()['AcceptanceRefused'] is module.AcceptanceRefused
assert all(not getattr(value, '__file__', '').startswith(sys.argv[2])
           for name, value in sys.modules.items() if name.startswith('_dbcrypt_acceptance'))
"""
    environment = tool.probe_environment(tmp_path / "home")
    child = subprocess.run(
        [sys.executable, "-c", script, str(bundle), str(checkout)],
        cwd=unrelated,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert child.returncode == 0, child.stdout + child.stderr
    help_result = subprocess.run(
        [sys.executable, str(bundle / "tools/dbcrypt_acceptance.py"), "--help"],
        cwd=unrelated,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "assemble-windows-qualification" in help_result.stdout


def test_windows_inventory_uses_current_facade_platform(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulated Windows builders must inspect Scripts/Lib even on this inert host."""
    from types import SimpleNamespace

    tool = acceptance_tool("dbcrypt_acceptance")
    windows_bundle, posix_bundle = tmp_path / "windows", tmp_path / "posix"
    windows_site = windows_bundle / "wheel-env/Lib/site-packages"
    posix_site = posix_bundle / "wheel-env/lib/site-packages"
    windows_site.mkdir(parents=True)
    posix_site.mkdir(parents=True)
    monkeypatch.setattr(tool, "sys", SimpleNamespace(platform="win32"))
    assert tool._site_packages(windows_bundle) == windows_site
    monkeypatch.setattr(tool, "sys", SimpleNamespace(platform="linux"))
    assert tool._site_packages(posix_bundle) == posix_site
