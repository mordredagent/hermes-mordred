"""Installed-runtime Windows memory proof (C5c phase 2), issued outside every lock.

A proof records that the C4-selected installed Hermes interpreter, with its own
``mordred_hermes`` under that environment root, installed the memory seam
through its real startup bootstrap and round-tripped a parent challenge with
the profile's CNG-unwrapped memory key in RAM. Custody preconditions are
captured load-only and rechecked after the child exits; lifecycle consumers
revalidate the proof under their own locks with
:func:`validate_windows_runtime_proof`. There is no force, bool or callback
substitute, and the only constructor path is this module's factory.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import weakref
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

from .. import _config_io, _windows_runtime
from .._private_fs import FileIdentity, PrivateDirectory, PrivateFSError, open_private_directory
from . import _runtime_probe
from ._windows_custody import WindowsCustodySession, windows_custody_session

__all__ = [
    "PROOF_TTL_SECONDS",
    "WindowsRuntimeProof",
    "WindowsRuntimeProofError",
    "prove_windows_memory_runtime",
    "require_issued_proof",
    "validate_windows_runtime_proof",
]

#: A proof older than this (monotonic seconds) refuses at consumption.
PROOF_TTL_SECONDS: Final = 600.0
#: Authoritative interpreter override shared with C4 installer/wizard callers.
PYTHON_OVERRIDE_ENV: Final = "MORDRED_HERMES_PYTHON"
#: Test-only native-backend injection; preserved only for a source-checkout test module.
INJECT_BACKEND_ENV: Final = "MORDRED_TEST_INJECT_BACKEND"
#: The authoritative helper selector the installed runtime itself honors.
HELPER_OVERRIDE_ENV: Final = "MORDRED_WINKEY_HELPER"

_OUTPUT_LIMIT: Final = 4096
_STDERR_LIMIT: Final = 2048
#: After the child exits, readers get this long to reach end-of-file.
_DRAIN_SECONDS: Final = 5.0
_SCRIPT_NAME: Final = "hermes"  # engages the runtime .pth bootstrap exactly like a Hermes start
_REPORT_KEYS: Final = frozenset({"module", "helper", "seam", "generation", "wrapped_sha256", "challenge_sha256"})
_SEAMS: Final = frozenset({"A", "B", "C"})

# The child never prints key bytes. Stray stdout writes (including fd-level
# writes from native code) go to stderr; only the final report reaches the
# saved stdout descriptor. Exit codes and exception type names are the only
# diagnostics.
_CHILD_SOURCE: Final = r"""
import hashlib, json, os, sys


def _fail(code, detail=""):
    sys.stderr.write("mordred-proof:%d:%s\n" % (code, detail))
    sys.stderr.flush()
    return code


def _main(out):
    try:
        line = sys.stdin.buffer.readline(66)
        challenge = bytes.fromhex(line.decode("ascii").strip())
    except Exception as exc:
        return _fail(10, type(exc).__name__)
    if len(challenge) != 32:
        return _fail(10, "challenge")
    try:
        inject = os.environ.get("MORDRED_TEST_INJECT_BACKEND")
        if inject:
            import importlib.util
            spec = importlib.util.spec_from_file_location("_mordred_proof_injection", inject)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.install()
        from pathlib import Path
        import mordred_hermes
        from mordred_hermes import _windows_runtime
        root = _windows_runtime.environment_root(Path(sys.executable))
        module_path = os.path.realpath(mordred_hermes.__file__)
        base = None if root is None else os.path.normcase(os.path.realpath(root))
        if base is None or os.path.commonpath([os.path.normcase(module_path), base]) != base:
            return _fail(11, "module-outside-environment")
        from mordred_hermes.keyvault import _memory_hook
        if not _memory_hook.memory_hook_installed():
            return _fail(12, "memory-seam-not-installed")
        seam = _memory_hook.memory_seam_shape()
        from mordred_hermes.keyvault import _seckey_helper, memory_crypto
        from mordred_hermes.keyvault._windows_custody import windows_custody_session
        helper = _seckey_helper.find_winkey_helper()
        if not helper:
            return _fail(13, "helper-unavailable")
        with windows_custody_session(Path(os.environ["HERMES_HOME"])) as session:
            state = session.memory_state()
            if state.lease is None or state.wrapped_sha256 is None:
                return _fail(14, "memory-not-enrolled")
            key = session.load_memory_key()
        sealed = memory_crypto.seal(challenge, key=key, name="MEMORY.md")
        opened = memory_crypto.unseal(sealed, key=key, name="MEMORY.md")
        del key, sealed
        if opened != challenge:
            return _fail(15, "roundtrip")
        report = {
            "module": module_path,
            "helper": helper,
            "seam": seam,
            "generation": state.lease.generation,
            "wrapped_sha256": state.wrapped_sha256,
            "challenge_sha256": hashlib.sha256(opened + b"proof").hexdigest(),
        }
    except BaseException as exc:
        return _fail(19, type(exc).__name__)
    data = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    while data:
        data = data[os.write(out, data):]
    return 0


_out = os.dup(1)
os.dup2(2, 1)
sys.exit(_main(_out))
"""


class WindowsRuntimeProofError(RuntimeError):
    """Installed-runtime proof refused; ``reason`` is a stable sanitized code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"Windows installed-runtime memory proof refused ({reason}){': ' + detail if detail else ''}")
        self.reason = reason


_MINT = threading.local()
_ISSUED_LOCK = threading.Lock()
_ISSUED: weakref.WeakValueDictionary[int, WindowsRuntimeProof] = weakref.WeakValueDictionary()


@dataclass(frozen=True)
class WindowsRuntimeProof:
    """Immutable installed-runtime evidence; issued only by :func:`prove_windows_memory_runtime`."""

    python: Path
    module_path: str
    helper_path: str
    seam: str
    home_identity: FileIdentity
    principal_sid: bytes
    profile_nonce: bytes
    memory_generation: str
    wrapped_digest: bytes
    challenge: bytes
    epoch: int
    proved_at: float

    def __post_init__(self) -> None:
        # Direct construction and dataclasses.replace() both refuse; consumers
        # additionally require the exact issued object (copies are not issued).
        if not getattr(_MINT, "active", False):
            raise TypeError("WindowsRuntimeProof is issued only by prove_windows_memory_runtime")


@dataclass(frozen=True)
class _Captured:
    home: FileIdentity
    sid: bytes
    profile_nonce: str
    epoch: int
    generation: str
    wrapped_sha256: str


@dataclass(frozen=True)
class _ChildResult:
    returncode: int | None
    stdout: bytes
    stdout_overflow: bool
    stderr: bytes
    timed_out: bool
    incomplete: bool


def _clock() -> float:
    return time.monotonic()


def _require_unlocked() -> None:
    # The proof launches subprocesses and must never run inside a canonical
    # (custody/memory) session of this thread: a nested session would join it.
    if getattr(_config_io._local, "state", None) is not None:
        raise WindowsRuntimeProofError("locks-held", "run the proof outside every custody or memory session")


def _capture(custody: WindowsCustodySession) -> _Captured:
    state = custody.memory_state()
    if state.lease is None or state.wrapped_sha256 is None:
        raise WindowsRuntimeProofError("custody-not-enrolled", "memory custody is not enrolled")
    binding = custody.profile_binding()
    if binding.pending:
        raise WindowsRuntimeProofError("custody-pending", "unresolved custody journal")
    return _Captured(
        binding.home, binding.sid, binding.profile_nonce, binding.epoch, state.lease.generation, state.wrapped_sha256
    )


def _capture_home(home: Path) -> _Captured:
    """Load-only capture; the custody session is closed before returning."""
    with windows_custody_session(home) as custody:
        return _capture(custody)


def _select_interpreter(home: Path, python: str | os.PathLike[str] | None) -> tuple[Path, Path]:
    """C4 selection; an explicit or environment override never falls back."""
    override = os.fspath(python) if python is not None else os.environ.get(PYTHON_OVERRIDE_ENV)
    if override is not None:
        candidate = Path(override).expanduser()
        if candidate.name.lower() == "pythonw.exe":
            if not candidate.is_file():
                raise WindowsRuntimeProofError("interpreter-invalid", "pythonw override does not exist")
            candidate = candidate.with_name("python.exe")
        override = os.fspath(candidate)
    selected = _windows_runtime.resolve_windows_python(home, override=override)
    root = None if selected is None else _windows_runtime.environment_root(selected)
    if selected is None or root is None:
        raise WindowsRuntimeProofError("interpreter-invalid", "no validated installed Hermes interpreter")
    return selected, root


def _source_test_tree(package_file: str | None = None) -> Path | None:
    """``<checkout>/tests`` only when this package runs from a source checkout."""
    if package_file is None:
        import mordred_hermes

        package_file = mordred_hermes.__file__
    if package_file is None:
        return None
    package = Path(os.path.realpath(package_file)).parent
    root = package.parent.parent
    tests = root / "tests"
    if package.parent.name != "src" or not (root / "pyproject.toml").is_file():
        return None
    return tests if (tests / "__init__.py").is_file() else None


def _preserved_injection(environ: Mapping[str, str], *, package_file: str | None = None) -> str | None:
    """Keep the test backend selector only for a pytest run naming a checkout test module."""
    value = environ.get(INJECT_BACKEND_ENV)
    if not value or "pytest" not in sys.modules or not environ.get("PYTEST_CURRENT_TEST"):
        return None
    tests = _source_test_tree(package_file)
    candidate = Path(value)
    if tests is None or not candidate.is_absolute() or candidate.suffix != ".py" or candidate.is_symlink():
        return None
    resolved = Path(os.path.realpath(candidate))
    if not resolved.is_file() or not resolved.is_relative_to(tests) or ".." in candidate.parts:
        return None
    return os.fspath(resolved)


def _child_environment(environ: Mapping[str, str], home: Path) -> dict[str, str]:
    """C4 scrub plus every Python/Mordred/ambient-key selector except the helper override."""
    injection = _preserved_injection(environ)
    env = {}
    for key, value in _windows_runtime.scrubbed_environment(environ).items():
        folded = key.upper()
        if folded.startswith("PYTHON") or folded in ("HERMES_MEMORY_KEY", "HERMES_HOME"):
            continue
        if folded.startswith("MORDRED_") and folded != HELPER_OVERRIDE_ENV:
            continue
        env[key] = value
    env.update(
        HERMES_HOME=os.fspath(home),
        MORDRED_CONFIG_DECRYPT="0",
        PYTHONUTF8="1",
        PYTHONIOENCODING="utf-8",
        PYTHONNOUSERSITE="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    if injection is not None:
        env[INJECT_BACKEND_ENV] = injection
    return env


def _remove_script(private: PrivateDirectory) -> None:
    with private.transaction() as tx:
        try:
            identity = tx.stat(_SCRIPT_NAME).identity
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return
            raise
        tx.delete_file(_SCRIPT_NAME, expected_identity=identity)


@contextlib.contextmanager
def _probe_script() -> Iterator[Path]:
    """Task-owned exact-private directory holding the probe; removed afterwards.

    Cleanup covers the creation window too: a failed or uncertain write still
    removes whatever was published. A cleanup failure never masks the primary
    error; it only leaves the private directory behind.
    """
    directory = Path(tempfile.gettempdir()).resolve() / f"mordred-proof-{secrets.token_hex(16)}"
    try:
        with open_private_directory(directory, create=True) as private:
            try:
                with private.transaction() as tx:
                    tx.create_bytes(_SCRIPT_NAME, _CHILD_SOURCE.encode("utf-8"))
                yield directory / _SCRIPT_NAME
            finally:
                original = sys.exception()
                try:
                    _remove_script(private)
                except OSError as failure:
                    if original is None:
                        raise
                    original.add_note(f"probe script cleanup failed: {type(failure).__name__}")
    finally:
        # The C1 sidecar lock is the only other entry of this new private directory.
        with contextlib.suppress(OSError):
            (directory / ".mordred-fs.lock").unlink()
        with contextlib.suppress(OSError):
            directory.rmdir()


class _BoundedReader(threading.Thread):
    def __init__(self, stream: IO[bytes], limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self.data = bytearray()
        self.overflow = False

    def run(self) -> None:
        with contextlib.suppress(OSError, ValueError), self._stream:
            while chunk := os.read(self._stream.fileno(), 65536):
                room = self._limit - len(self.data)
                self.data += chunk[: max(room, 0)]
                self.overflow = self.overflow or len(chunk) > room


def _run_child(argv: list[str], *, env: dict[str, str], cwd: Path, stdin: bytes, timeout: float) -> _ChildResult:
    _require_unlocked()
    # Only the C4-validated interpreter and the task-owned private probe script run here.
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd
        )
    except OSError as exc:
        raise WindowsRuntimeProofError("launch-failed", type(exc).__name__) from exc
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    out = _BoundedReader(process.stdout, _OUTPUT_LIMIT)
    err = _BoundedReader(process.stderr, _STDERR_LIMIT)
    out.start()
    err.start()
    with contextlib.suppress(OSError):
        process.stdin.write(stdin)
    with contextlib.suppress(OSError):
        process.stdin.close()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    out.join(_DRAIN_SECONDS)
    err.join(_DRAIN_SECONDS)
    incomplete = out.is_alive() or err.is_alive()
    return _ChildResult(process.returncode, bytes(out.data), out.overflow, bytes(err.data), timed_out, incomplete)


def _sanitize(data: bytes) -> str:
    text = data[:_STDERR_LIMIT].decode("ascii", "replace")
    return re.sub(r"[^\x20-\x7e]+", " ", text).strip()


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate report key")
        result[key] = value
    return result


def _within(path: str, root: Path) -> bool:
    if not os.path.isabs(path):
        return False
    resolved, base = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(root))
    try:
        return resolved != base and os.path.commonpath([resolved, base]) == base
    except ValueError:  # different Windows drives
        return False


def _parse_report(result: _ChildResult) -> dict[str, str]:
    if result.timed_out:
        raise WindowsRuntimeProofError("runtime-timeout")
    if result.returncode != 0:
        raise WindowsRuntimeProofError("runtime-failed", f"exit {result.returncode}; {_sanitize(result.stderr)}")
    if result.incomplete:
        raise WindowsRuntimeProofError("output-unterminated", "an output stream stayed open after the child exited")
    data = result.stdout
    if result.stdout_overflow or len(data) > _OUTPUT_LIMIT:
        raise WindowsRuntimeProofError("output-oversized")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise WindowsRuntimeProofError("output-malformed", "expected exactly one report line")
    try:
        report = json.loads(data[:-1].decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError, RecursionError):
        raise WindowsRuntimeProofError("output-malformed", "report is not strict JSON") from None
    if not isinstance(report, dict) or set(report) != _REPORT_KEYS:
        raise WindowsRuntimeProofError("output-malformed", "unexpected report fields")
    if not all(isinstance(value, str) and value for value in report.values()):
        raise WindowsRuntimeProofError("output-malformed", "report values must be non-empty strings")
    return report


def _verify_report(
    report: dict[str, str], captured: _Captured, challenge: bytes, root: Path, env: Mapping[str, str]
) -> None:
    expected = hashlib.sha256(challenge + b"proof").hexdigest()
    if not hmac.compare_digest(report["challenge_sha256"], expected):
        raise WindowsRuntimeProofError("output-mismatch", "challenge digest")
    if report["generation"] != captured.generation or report["wrapped_sha256"] != captured.wrapped_sha256:
        raise WindowsRuntimeProofError("output-mismatch", "custody generation or wrapped key")
    if report["seam"] not in _SEAMS:
        raise WindowsRuntimeProofError("output-mismatch", "unsupported memory seam")
    if not _within(report["module"], root):
        raise WindowsRuntimeProofError("module-outside-environment")
    helper = report["helper"]
    selected = env.get(HELPER_OVERRIDE_ENV)
    if not os.path.isabs(helper) or not os.path.isfile(helper):
        raise WindowsRuntimeProofError("helper-mismatch", "helper is not an existing absolute path")
    if selected is not None and _normalized(selected) != _normalized(helper):
        raise WindowsRuntimeProofError("helper-mismatch", "helper differs from the selected override")


def _normalized(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expanduser(path)))


@contextlib.contextmanager
def _minting() -> Iterator[None]:
    _MINT.active = True
    try:
        yield
    finally:
        _MINT.active = False


def _issue(proof: WindowsRuntimeProof) -> WindowsRuntimeProof:
    with _ISSUED_LOCK:
        _ISSUED[id(proof)] = proof
    return proof


def prove_windows_memory_runtime(
    home: Path, *, python: str | os.PathLike[str] | None = None, timeout: float = 20.0
) -> WindowsRuntimeProof:
    """Prove the installed runtime can load and use this profile's memory key.

    Call outside every custody/memory lock. Steps: load-only custody capture;
    C4 interpreter selection (``python`` or ``MORDRED_HERMES_PYTHON`` is
    authoritative and never falls back); stopped-gateway gate; scrubbed child
    with a private probe script and a 32-byte stdin challenge; strict bounded
    report verification; load-only post-check that identity, SID, nonce,
    generation, wrapped digest and epoch are unchanged.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive finite number of seconds")
    _require_unlocked()
    captured = _capture_home(home)
    selected, root = _select_interpreter(home, python)
    _runtime_probe.require_stopped_windows_gateways(home)
    challenge = secrets.token_bytes(32)
    env = _child_environment(os.environ, home)
    with _probe_script() as script:
        result = _run_child(
            [os.fspath(selected), os.fspath(script)],
            env=env,
            cwd=script.parent,
            stdin=challenge.hex().encode("ascii") + b"\n",
            timeout=float(timeout),
        )
    report = _parse_report(result)
    _verify_report(report, captured, challenge, root, env)
    try:
        unchanged = _capture_home(home) == captured
    except WindowsRuntimeProofError as exc:
        raise WindowsRuntimeProofError("proof-stale", exc.reason) from exc
    if not unchanged:
        raise WindowsRuntimeProofError("proof-stale", "custody changed while the runtime was proven")
    with _minting():
        proof = WindowsRuntimeProof(
            python=selected,
            module_path=report["module"],
            helper_path=report["helper"],
            seam=report["seam"],
            home_identity=captured.home,
            principal_sid=captured.sid,
            profile_nonce=bytes.fromhex(captured.profile_nonce),
            memory_generation=captured.generation,
            wrapped_digest=bytes.fromhex(captured.wrapped_sha256),
            challenge=challenge,
            epoch=captured.epoch,
            proved_at=_clock(),
        )
    return _issue(proof)


def require_issued_proof(proof: WindowsRuntimeProof) -> None:
    """Refuse copies, forgeries and expired proofs before any lock is taken."""
    if not isinstance(proof, WindowsRuntimeProof):
        raise WindowsRuntimeProofError("proof-not-issued")
    with _ISSUED_LOCK:
        issued = _ISSUED.get(id(proof)) is proof
    if not issued:
        raise WindowsRuntimeProofError("proof-not-issued")
    age = _clock() - proof.proved_at
    if not 0.0 <= age <= PROOF_TTL_SECONDS:
        raise WindowsRuntimeProofError("proof-expired")


def validate_windows_runtime_proof(custody: WindowsCustodySession, proof: WindowsRuntimeProof) -> None:
    """Revalidate a proof against live custody held by the caller; no IO beyond custody reads."""
    require_issued_proof(proof)
    try:
        current = _capture(custody)
    except WindowsRuntimeProofError as exc:
        raise WindowsRuntimeProofError("proof-stale", exc.reason) from exc
    if current != _Captured(
        proof.home_identity,
        proof.principal_sid,
        proof.profile_nonce.hex(),
        proof.epoch,
        proof.memory_generation,
        proof.wrapped_digest.hex(),
    ):
        raise WindowsRuntimeProofError("proof-stale", "custody identity, generation, wrapped key or epoch changed")
