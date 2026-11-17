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
for dependency in (module._common, module._evidence, module._execution, module._windows):
    assert Path(dependency.__file__).resolve().parent == path.parent.resolve()
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


@pytest.mark.parametrize("copied_first", [False, True], ids=["checkout-first", "bundle-first"])
def test_tool_copies_keep_their_own_implementations_in_one_process(tmp_path: Path, copied_first: bool) -> None:
    """A cached verifier must not supply another physical copy's source authority."""
    import shutil
    import subprocess
    import sys

    checkout = Path(__file__).resolve().parents[1]
    bundle = tmp_path / "bundle"
    (bundle / "tools").mkdir(parents=True)
    (bundle / "tests").mkdir()
    for source in (checkout / "tools").glob("*dbcrypt_acceptance*.py"):
        shutil.copyfile(source, bundle / "tools" / source.name)
    shutil.copyfile(checkout / "tests/_dbcrypt_acceptance_native.py", bundle / "tests/_dbcrypt_acceptance_native.py")
    script = """
import importlib.util
from pathlib import Path
import runpy
import sys

checkout, bundle = (Path(value).resolve() for value in sys.argv[1:3])
first, second = (bundle, checkout) if sys.argv[3] == 'True' else (checkout, bundle)
# Both directories already occur on sys.path, with the second below the first.
# Merely checking membership or deleting fixed-name module caches is insufficient.
sys.path[:0] = [str(first / 'tools')]
sys.path.append(str(second / 'tools'))
before_path = sys.path.copy()
spec = importlib.util.spec_from_file_location('arbitrary.first_copy', first / 'tools/dbcrypt_acceptance.py')
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
facades = {first: vars(loaded), second: runpy.run_path(str(second / 'tools/dbcrypt_acceptance.py'))}
for root, facade in facades.items():
    common = sys.modules[facade['AcceptanceRefused'].__module__]
    for module in (common, facade['_evidence'], facade['_execution'], facade['_windows']):
        assert Path(module.__file__).resolve().parent == root / 'tools', (root, module.__file__)
        assert module.AcceptanceRefused is facade['AcceptanceRefused']
    collector = runpy.run_path(str(root / 'tests/_dbcrypt_acceptance_native.py'))
    collected = collector['_tool']()
    assert collected['AcceptanceRefused'] is facade['AcceptanceRefused']
    assert collected['_windows'] is facade['_windows']
assert facades[first]['AcceptanceRefused'] is not facades[second]['AcceptanceRefused']
assert sys.path == before_path
for root, facade in facades.items():
    try:
        facade['load_stop_receipt'](root / 'missing-receipt.json')
    except facade['AcceptanceRefused']:
        pass
    else:
        raise AssertionError('invalid receipt did not raise its own facade exception')

# Exercise both Windows __file__-derived source-authority boundaries. Replace
# only the downstream parser/selection boundary, after the real caller computes
# the path; receipt/hash reads and the functions selecting the authority stay real.
for number, (root, facade) in enumerate(facades.items()):
    directory = bundle.parent / ('authority-' + str(number))
    directory.mkdir()
    path = directory / 'manifest.json'
    path.write_text('{}')
    reference = {'path': path.name, 'sha256': facade['sha256_file'](path)}
    windows = facade['_windows']
    seen = []
    original = windows.validate_windows_qualification
    def qualification(directory, *, checkout, _api):
        seen.append(checkout)
        return {'manifest_sha256': 'a' * 64, 'source': {'dll_sha256': 'b' * 64}}
    try:
        windows.validate_windows_qualification = qualification
        facade['_phase_qualification']({
            'platform': 'win32', 'qualification_evidence': reference, 'acceptance_kind': 'candidate',
            'mode': 'source', 'native_facts': {
                'qualification_manifest_sha256': 'a' * 64, 'dll': {'sha256': 'b' * 64},
            },
        }, directory)
    finally:
        windows.validate_windows_qualification = original
    assert seen == [root], seen

    class SelectedAuthority(Exception):
        pass
    calls = []
    def nodes(checkout, *, release):
        calls.append((checkout, release))
        if not release:
            raise SelectedAuthority
        return ['inert']
    original_nodes, original_fixture = windows.windows_vfs_required_nodes, windows._fixture_descriptor
    try:
        windows.windows_vfs_required_nodes = nodes
        windows._fixture_descriptor = lambda path: ({}, set())
        try:
            facade['_validate_packaged_result'](directory, {
                'schema_version': 1, 'kind': 'packaged_windows_vfs_result', 'status': 'passed',
                'mode': 'source', 'diagnostic_manifest_sha256': 'd' * 64,
                'fixtures_sha256': reference['sha256'], 'fixtures_descriptor': reference, 'artifacts': {},
            }, mode='source', bundle={}, proof={}, proof_directory=directory,
               diagnostic={'manifest_sha256': 'd' * 64}, fixtures={'manifest_sha256': reference['sha256']})
        except SelectedAuthority:
            pass
        else:
            raise AssertionError('qualification did not reach the source selection boundary')
    finally:
        windows.windows_vfs_required_nodes, windows._fixture_descriptor = original_nodes, original_fixture
    assert calls == [(root, True), (root, False)], calls
"""
    environment = acceptance_tool("dbcrypt_acceptance").probe_environment(tmp_path / "home")
    child = subprocess.run(
        [sys.executable, "-c", script, str(checkout), str(bundle), str(copied_first)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert child.returncode == 0, child.stdout + child.stderr
