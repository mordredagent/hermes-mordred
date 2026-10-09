"""Installed-runtime Windows memory proof through a real child interpreter.

The "installed runtime" is a non-editable environment built from this test
venv's real interpreter: a fresh venv whose site-packages holds a copy of the
package and the packaged ``.pth`` bootstrap lines, with the test venv's
site-packages exposed for dependencies. The native CNG boundary is the
test-only file-backed P-256 backend (``tests/_windows_proof_runtime.py``)
selected through ``MORDRED_TEST_INJECT_BACKEND``. Custody, MRKW and AES-GCM are
real; no proof is ever hand-built.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import sysconfig
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import mordred_hermes
from mordred_hermes import _config_io as cio
from mordred_hermes import _windows_runtime
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.keyvault import _windows_processes
from mordred_hermes.keyvault._runtime_probe import GatewayDiscoveryUnavailable, GatewayRuntime
from tests import _windows_proof_runtime as injected
from tests.test_windows_custody import fs as fs

ROOT = Path(__file__).resolve().parents[1]
INJECTION = Path(os.path.realpath(injected.__file__))


def proof_module():
    from mordred_hermes.keyvault import _windows_proof

    return _windows_proof


@pytest.fixture(scope="session")
def installed_runtime(tmp_path_factory):
    """A real non-editable Python environment using this venv's interpreter."""
    root = Path(os.path.realpath(tmp_path_factory.mktemp("installed-runtime"))) / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root)], check=True, timeout=300)
    python = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    purelib = Path(
        subprocess.run(
            [str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout.strip()
    )
    package = Path(os.path.realpath(mordred_hermes.__file__)).parent
    shutil.copytree(package, purelib / "mordred_hermes", ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("mordred_hermes_runtime.pth", "mordred_hermes_config_decrypt.pth"):
        shutil.copyfile(ROOT / "packaging" / "pth" / name, purelib / name)
    # Path lines only: the test venv's own .pth files (editable source) never run.
    dependencies = sorted({sysconfig.get_paths()["purelib"], sysconfig.get_paths()["platlib"]})
    (purelib / "_mordred_test_dependencies.pth").write_text("\n".join(dependencies) + "\n", encoding="utf-8")
    return python


class Launches:
    """Subprocess spy proving no launch ever happens inside a canonical session."""

    def __init__(self, monkeypatch):
        self.argv: list[list[str]] = []
        self.processes: list[subprocess.Popen] = []
        self.fail_child: OSError | None = None
        real = subprocess.Popen

        def guarded(argv, *args, **kwargs):
            assert getattr(cio._local, "state", None) is None, "subprocess launched under custody/memory locks"
            self.argv.append([str(part) for part in argv])
            if self.fail_child is not None and str(argv[-1]).endswith(("hermes", "probe")):
                raise self.fail_child
            process = real(argv, *args, **kwargs)
            self.processes.append(process)
            return process

        monkeypatch.setattr(subprocess, "Popen", guarded)


def known_empty(home, **kwargs):
    return _windows_processes.GatewayInventory("known", (), ())


@pytest.fixture
def proof_env(fs, monkeypatch, installed_runtime, tmp_path):
    custody, storage, home, _ = fs
    backend = injected.backend_for(home)
    injected.emulate(monkeypatch.setattr, backend)
    monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", known_empty)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "tempdir", os.path.realpath(scratch))
    monkeypatch.setenv("MORDRED_TEST_INJECT_BACKEND", str(INJECTION))
    for name in ("MORDRED_HERMES_PYTHON", "MORDRED_WINKEY_HELPER", "HERMES_MEMORY_KEY"):
        monkeypatch.delenv(name, raising=False)
    return SimpleNamespace(
        custody=custody,
        storage=storage,
        home=home,
        backend=backend,
        python=installed_runtime,
        scratch=scratch,
        launches=Launches(monkeypatch),
    )


def enroll(env):
    with env.custody.windows_custody_session(env.home, create=True, backend=env.backend) as owner:
        owner.enroll_memory()
        return owner.lease("memory")


def prove(env, **kwargs):
    kwargs.setdefault("python", env.python)
    return proof_module().prove_windows_memory_runtime(env.home, **kwargs)


def refused(reason):
    return pytest.raises(proof_module().WindowsRuntimeProofError, match=rf"\({reason}\)")


def test_proof_binds_installed_runtime_and_custody(proof_env):
    env = proof_env
    lease = enroll(env)
    proof = prove(env)
    assert proof.python == env.python
    runtime_root = Path(os.path.realpath(env.python.parent.parent))
    assert Path(proof.module_path).is_relative_to(runtime_root)
    assert proof.module_path != os.path.realpath(mordred_hermes.__file__), "editable source cannot prove"
    assert os.path.realpath(proof.helper_path) == str(INJECTION)
    assert proof.seam in {"A", "B", "C"}
    assert proof.memory_generation == lease.generation
    wrapped = (env.home / "mordred" / "memory-key.wrapped").read_bytes()
    assert proof.wrapped_digest == hashlib.sha256(wrapped).digest()
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        binding = owner.profile_binding()
    assert (proof.home_identity, proof.principal_sid, proof.epoch) == (binding.home, injected.SID, binding.epoch)
    assert proof.profile_nonce.hex() == binding.profile_nonce
    assert len(proof.challenge) == 32
    assert 0 <= time.monotonic() - proof.proved_at < 60
    # Validation subprocess, then the child, each outside every lock.
    assert len(env.launches.argv) == 2
    assert env.launches.argv[1][1].endswith("hermes")
    assert list(env.scratch.iterdir()) == [], "probe script directory was not removed"
    assert not (env.home / "memories").exists()
    assert not (env.home / "mordred" / "memory-vault.marker").exists()


def test_proof_cannot_be_constructed_replaced_or_copied(proof_env):
    module = proof_module()
    enroll(proof_env)
    proof = prove(proof_env)
    fields = {field.name: getattr(proof, field.name) for field in dataclasses.fields(proof)}
    with pytest.raises(TypeError):
        module.WindowsRuntimeProof(**fields)
    with pytest.raises(TypeError):
        dataclasses.replace(proof, epoch=proof.epoch + 1)
    with refused("proof-not-issued"):
        module.require_issued_proof(copy.copy(proof))
    module.require_issued_proof(proof)


def test_unenrolled_custody_refuses_before_any_launch(proof_env):
    with refused("custody-not-enrolled"):
        prove(proof_env)
    assert proof_env.launches.argv == []


def test_pending_journal_refuses_before_any_launch(proof_env, monkeypatch):
    env = proof_env
    enroll(env)

    def denied(*args, **kwargs):
        raise env.custody.CustodyError("native unavailable")

    monkeypatch.setattr(env.backend, "generate_enclave_key", denied)
    with (
        pytest.raises(env.custody.CustodyError),
        env.custody.windows_custody_session(env.home, backend=env.backend) as owner,
    ):
        owner.enroll_role("audit")
    assert (env.home / "mordred" / "windows-audit.pending.json").exists()
    with refused("custody-pending"):
        prove(env)
    assert env.launches.argv == []


@pytest.mark.parametrize("source", ["argument", "environment", "pythonw"])
def test_override_validation_failure_refuses_without_fallback(proof_env, monkeypatch, tmp_path, source):
    env = proof_env
    enroll(env)
    tried = []
    real = _windows_runtime.validate_windows_python

    def spy(python, **kwargs):
        tried.append(python)
        return real(python, **kwargs)

    monkeypatch.setattr(_windows_runtime, "validate_windows_python", spy)
    invalid = tmp_path / "other" / ("pythonw.exe" if source == "pythonw" else "python.exe")
    if source == "environment":
        monkeypatch.setenv("MORDRED_HERMES_PYTHON", str(invalid))
        kwargs = {"python": None}
    else:
        kwargs = {"python": invalid}
    with refused("interpreter-invalid"):
        prove(env, **kwargs)
    assert tried == ([] if source == "pythonw" else [invalid])
    assert env.launches.argv == []


@pytest.mark.parametrize("state", ["running", "unknown"])
def test_gateway_inventory_refuses_before_child_launch(proof_env, monkeypatch, state):
    env = proof_env
    enroll(env)

    def inventory(home, **kwargs):
        if state == "running":
            return _windows_processes.GatewayInventory("known", (GatewayRuntime(4242, env.python),), ())
        return _windows_processes.GatewayInventory("unknown", (), ("pid=7:owner-denied-plausible",))

    monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", inventory)
    with pytest.raises(GatewayDiscoveryUnavailable):
        prove(env)
    # Only the C4 interpreter validation ran; the proof child never started.
    assert len(env.launches.argv) == 1
    assert "-c" in env.launches.argv[0]


CRAFTED = r"""
import hashlib, json, os, sys, time
challenge = bytes.fromhex(sys.stdin.readline().strip())
report = {
    "module": os.path.realpath(__import__("mordred_hermes").__file__),
    "helper": GENERATION_HELPER,
    "seam": "B",
    "generation": GENERATION,
    "wrapped_sha256": WRAPPED,
    "challenge_sha256": hashlib.sha256(challenge + b"proof").hexdigest(),
}
MUTATION
sys.stdout.write(OUTPUT)
sys.stdout.flush()
sys.exit(EXIT)
"""

CASES = {
    "malformed": ("pass", "'{not json\\n'", 0, "output-malformed"),
    "oversized": ("pass", "json.dumps(report) + ' ' * 5000 + '\\n'", 0, "output-oversized"),
    "extra-line": ("pass", "json.dumps(report) + '\\nextra\\n'", 0, "output-malformed"),
    "no-newline": ("pass", "json.dumps(report)", 0, "output-malformed"),
    "duplicate-key": ("pass", 'json.dumps(report)[:-1] + \', "seam": "B"}\\n\'', 0, "output-malformed"),
    "extra-key": ("report['key'] = 'x'", "json.dumps(report) + '\\n'", 0, "output-malformed"),
    "wrong-digest": ("report['challenge_sha256'] = '0' * 64", "json.dumps(report) + '\\n'", 0, "output-mismatch"),
    "wrong-generation": ("report['generation'] = '1' * 64", "json.dumps(report) + '\\n'", 0, "output-mismatch"),
    "wrong-wrapped": ("report['wrapped_sha256'] = '2' * 64", "json.dumps(report) + '\\n'", 0, "output-mismatch"),
    "unsupported-seam": ("report['seam'] = 'D'", "json.dumps(report) + '\\n'", 0, "output-mismatch"),
    "outside-root": (
        "report['module'] = os.path.realpath(sys.argv[0])",
        "json.dumps(report) + '\\n'",
        0,
        "module-outside-environment",
    ),
    "relative-helper": ("report['helper'] = 'helper.exe'", "json.dumps(report) + '\\n'", 0, "helper-mismatch"),
    "nonzero-exit": ("pass", "json.dumps(report) + '\\n'", 3, "runtime-failed"),
}


@pytest.mark.parametrize("case", list(CASES))
def test_child_protocol_violations_refuse(proof_env, monkeypatch, case):
    env = proof_env
    lease = enroll(env)
    wrapped = hashlib.sha256((env.home / "mordred" / "memory-key.wrapped").read_bytes()).hexdigest()
    mutation, output, code, reason = CASES[case]
    source = (
        CRAFTED.replace("GENERATION_HELPER", repr(str(INJECTION)))
        .replace("GENERATION", repr(lease.generation))
        .replace("WRAPPED", repr(wrapped))
        .replace("MUTATION", mutation)
        .replace("OUTPUT", output)
        .replace("EXIT", str(code))
    )
    monkeypatch.setattr(proof_module(), "_CHILD_SOURCE", source)
    with refused(reason):
        prove(env)


def test_crafted_control_case_is_accepted(proof_env, monkeypatch):
    """The crafted protocol driver itself is valid, so each violation is isolated."""
    env = proof_env
    lease = enroll(env)
    wrapped = hashlib.sha256((env.home / "mordred" / "memory-key.wrapped").read_bytes()).hexdigest()
    source = (
        CRAFTED.replace("GENERATION_HELPER", repr(str(INJECTION)))
        .replace("GENERATION", repr(lease.generation))
        .replace("WRAPPED", repr(wrapped))
        .replace("MUTATION", "pass")
        .replace("OUTPUT", "json.dumps(report) + '\\n'")
        .replace("EXIT", "0")
    )
    monkeypatch.setattr(proof_module(), "_CHILD_SOURCE", source)
    assert prove(env).seam == "B"


def test_child_timeout_refuses_and_kills(proof_env, monkeypatch):
    env = proof_env
    enroll(env)
    monkeypatch.setattr(proof_module(), "_CHILD_SOURCE", "import time\ntime.sleep(60)\n")
    started = time.monotonic()
    with refused("runtime-timeout"):
        prove(env, timeout=1.0)
    assert time.monotonic() - started < 30
    child = env.launches.processes[-1]
    assert child.poll() is not None, "timed-out proof child is still running"
    if os.name != "nt":
        assert child.returncode == -signal.SIGKILL
    assert list(env.scratch.iterdir()) == []


def test_custody_change_during_child_is_stale(proof_env, monkeypatch):
    env = proof_env
    enroll(env)
    module = proof_module()
    real = module._run_child

    def child_then_enroll_audit(*args, **kwargs):
        result = real(*args, **kwargs)
        with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
            owner.enroll_role("audit")
        return result

    monkeypatch.setattr(module, "_run_child", child_then_enroll_audit)
    with refused("proof-stale"):
        prove(env)


def test_real_child_failure_reports_sanitized_code(proof_env, monkeypatch):
    """A failing installed child reports only its code and exception type name."""
    env = proof_env
    enroll(env)
    source = proof_module()._CHILD_SOURCE.replace("helper = _seckey_helper.find_winkey_helper()", "helper = None")
    monkeypatch.setattr(proof_module(), "_CHILD_SOURCE", source)
    with refused("runtime-failed") as failure:
        prove(env)
    assert "mordred-proof:13:helper-unavailable" in str(failure.value)


def test_proof_inside_custody_session_refuses(proof_env):
    env = proof_env
    enroll(env)
    with env.custody.windows_custody_session(env.home, backend=env.backend), refused("locks-held"):
        prove(env)
    assert env.launches.argv == []


@pytest.mark.parametrize("timeout", [0, -1.0, float("nan"), float("inf"), True])
def test_invalid_timeout_refuses_before_io(proof_env, timeout):
    with pytest.raises(ValueError):
        prove(proof_env, timeout=timeout)
    assert proof_env.launches.argv == []


# --- child environment scrub -------------------------------------------------


def test_child_environment_scrubs_bypasses_and_keeps_test_injection(proof_env):
    module = proof_module()
    environ = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": "/evil",
        "PYTHONHOME": "/evil",
        "PYTHONSTARTUP": "/evil.py",
        "PYTHONINSPECT": "1",
        "HERMES_MEMORY_KEY": "11" * 32,
        "HERMES_HOME": "/other",
        "UV_PYTHON": "/evil",
        "MORDRED_CONFIG_DECRYPT": "1",
        "MORDRED_SEKEY_UNATTENDED": "1",
        "MORDRED_HERMES_PYTHON": "/evil",
        "MORDRED_WINKEY_HELPER": "C:/owned/winkey-helper.exe",
        "MORDRED_TEST_INJECT_BACKEND": str(INJECTION),
        "PYTEST_CURRENT_TEST": "tests/x.py::y (call)",
    }
    env = module._child_environment(environ, proof_env.home)
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "HERMES_MEMORY_KEY", "UV_PYTHON"):
        assert name not in env
    assert "MORDRED_SEKEY_UNATTENDED" not in env and "MORDRED_HERMES_PYTHON" not in env
    assert env["MORDRED_CONFIG_DECRYPT"] == "0"
    assert env["HERMES_HOME"] == os.fspath(proof_env.home)
    assert env["MORDRED_WINKEY_HELPER"] == "C:/owned/winkey-helper.exe"
    assert env["MORDRED_TEST_INJECT_BACKEND"] == str(INJECTION)
    assert env["PYTHONNOUSERSITE"] == "1"


def _injection(environ_value, *, pytest_marker=True, package_file=None):
    environ = {"MORDRED_TEST_INJECT_BACKEND": environ_value}
    if pytest_marker:
        environ["PYTEST_CURRENT_TEST"] = "tests/x.py::y (call)"
    return proof_module()._preserved_injection(environ, package_file=package_file)


def test_injection_dropped_outside_pytest():
    assert _injection(str(INJECTION)) == str(INJECTION)
    assert _injection(str(INJECTION), pytest_marker=False) is None
    env = proof_module()._child_environment({"MORDRED_TEST_INJECT_BACKEND": str(INJECTION)}, Path("/home"))
    assert "MORDRED_TEST_INJECT_BACKEND" not in env


def test_injection_dropped_for_modules_outside_test_tree(tmp_path):
    outside = tmp_path / "backend.py"
    outside.write_text("def install():\n    pass\n", encoding="utf-8")
    assert _injection(str(outside)) is None
    traversal = ROOT / "tests" / ".." / "src" / "mordred_hermes" / "__init__.py"
    assert _injection(str(traversal)) is None
    assert _injection("tests/_windows_proof_runtime.py") is None  # relative
    assert _injection(str(ROOT / "tests" / "__init__.py.txt")) is None
    link = tmp_path / "link.py"
    try:
        link.symlink_to(INJECTION)
    except OSError:  # Windows tokens without the symlink privilege
        return
    assert _injection(str(link)) is None


def test_injection_dropped_for_installed_package(tmp_path):
    site = tmp_path / "venv" / "Lib" / "site-packages" / "mordred_hermes"
    site.mkdir(parents=True)
    (site / "__init__.py").write_text("", encoding="utf-8")
    assert proof_module()._source_test_tree(str(site / "__init__.py")) is None
    assert _injection(str(INJECTION), package_file=str(site / "__init__.py")) is None


def test_probe_directory_is_exact_private(proof_env, monkeypatch):
    module = proof_module()
    with module._probe_script() as script:
        assert script.name == "hermes"
        with open_private_directory(script.parent) as directory:
            assert directory.read_bytes("hermes", max_bytes=1 << 20) == module._CHILD_SOURCE.encode()
        assert script.parent.parent == Path(os.path.realpath(proof_env.scratch))
    assert not script.parent.exists()


def test_child_requires_the_installed_startup_bootstrap(proof_env, monkeypatch):
    """Without the Hermes-start .pth engagement the installed seam is not wrapped."""
    env = proof_env
    enroll(env)
    monkeypatch.setattr(proof_module(), "_SCRIPT_NAME", "probe")
    with refused("runtime-failed") as failure:
        prove(env)
    assert "mordred-proof:12:memory-seam-not-installed" in str(failure.value)


def test_child_launch_failure_is_classified_and_cleaned(proof_env):
    env = proof_env
    enroll(env)
    env.launches.fail_child = OSError(8, "Exec format error")
    with refused("launch-failed"):
        prove(env)
    assert list(env.scratch.iterdir()) == [], "probe directory survived a launch failure"


def test_reader_alive_after_clean_exit_is_unterminated(proof_env, monkeypatch):
    """A grandchild holding stdout open cannot pass as a complete report."""
    env = proof_env
    lease = enroll(env)
    wrapped = hashlib.sha256((env.home / "mordred" / "memory-key.wrapped").read_bytes()).hexdigest()
    mutation = "import subprocess; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)'], stdout=1)"
    source = (
        CRAFTED.replace("GENERATION_HELPER", repr(str(INJECTION)))
        .replace("GENERATION", repr(lease.generation))
        .replace("WRAPPED", repr(wrapped))
        .replace("MUTATION", mutation)
        .replace("OUTPUT", "json.dumps(report) + '\\n'")
        .replace("EXIT", "0")
    )
    module = proof_module()
    monkeypatch.setattr(module, "_CHILD_SOURCE", source)
    monkeypatch.setattr(module, "_DRAIN_SECONDS", 0.2)
    with refused("output-unterminated"):
        prove(env)


def test_probe_cleanup_covers_script_creation_failure(proof_env, monkeypatch):
    from mordred_hermes._private_fs import PrivateFSError

    env = proof_env
    enroll(env)
    if os.name == "nt":
        from mordred_hermes._private_fs import _windows_io as implementation
    else:
        from mordred_hermes._private_fs import _posix as implementation
    real = implementation._Transaction.create_bytes

    def published_then_failed(tx, name, data):
        real(tx, name, data)
        if name == "hermes":
            raise PrivateFSError("io", "injected", commit_state="uncertain")

    monkeypatch.setattr(implementation._Transaction, "create_bytes", published_then_failed)
    with pytest.raises(PrivateFSError):
        prove(env)
    assert list(env.scratch.iterdir()) == [], "probe script or directory survived a creation failure"
    assert env.launches.argv[-1][1:2] == ["-c"], "no child may start after a failed probe write"


def test_helper_differing_from_selected_override_refuses(proof_env, monkeypatch, tmp_path):
    env = proof_env
    enroll(env)
    other = tmp_path / "winkey-helper.exe"
    other.write_bytes(b"not the reported helper")
    monkeypatch.setenv("MORDRED_WINKEY_HELPER", str(other))
    with refused("helper-mismatch"):
        prove(env)


@pytest.fixture(scope="session")
def windows_layout_runtime(installed_runtime):
    """The same environment reached through ``Scripts/python.exe`` and ``pythonw.exe``."""
    scripts = installed_runtime.parent.parent / "Scripts"
    if os.name != "nt":
        scripts.mkdir(exist_ok=True)
        (scripts / "python.exe").symlink_to(os.path.realpath(installed_runtime))
        (scripts / "pythonw.exe").write_bytes(b"")
    return scripts


def test_existing_pythonw_maps_to_python_sibling(proof_env, windows_layout_runtime):
    env = proof_env
    enroll(env)
    proof = prove(env, python=windows_layout_runtime / "pythonw.exe")
    assert proof.python == windows_layout_runtime / "python.exe"
    assert proof.seam in {"A", "B", "C"}
