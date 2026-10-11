"""Explicit real-device acceptance for wizard entrances and shape-B drift backup.

Run in the installed candidate Hermes interpreter, with a test-owned HERMES_HOME
set before startup and MORDRED_LINUX_ORCHESTRATION_TEST=1. No mock, emulator,
force, full setup or account login is used. Failures retain the owned homes.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import stat
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "linux" or os.environ.get("MORDRED_LINUX_ORCHESTRATION_TEST") != "1",
        reason="requires explicit real Linux TPM orchestration acceptance",
    ),
]


_PROVENANCE = """
import importlib.metadata, inspect, json, sys
from pathlib import Path
import mordred_hermes
from tools import memory_tool
from mordred_hermes.keyvault._memory_hook import memory_hook_installed, memory_seam_shape
assert memory_seam_shape() == "B", "acceptance requires real shape-B Hermes"
assert memory_hook_installed(), "automatic Hermes startup hook absent"
for origin in (mordred_hermes.__file__, memory_tool.__file__, inspect.getfile(memory_tool.MemoryStore)):
    assert Path(origin).resolve().is_relative_to(Path(sys.prefix).resolve()), "module outside installed runtime"
print(json.dumps({"hermes_version": importlib.metadata.version("hermes-agent"),
 "memory_module": memory_tool.__file__, "memory_class": inspect.getfile(memory_tool.MemoryStore),
 "mordred": mordred_hermes.__file__, "shape": memory_seam_shape(), "automatic_hook": True}))
"""


def _run(home: Path, script: Path, source: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    script.write_text(source)
    # A script named hermes admits the normal installed startup hook, as in
    # test_linux_telegram_tpm.py; the hook is never installed by this harness.
    return subprocess.run(
        [sys.executable, str(script)],
        env=dict(env, HERMES_HOME=str(home)),
        cwd=script.parent,
        text=True,
        capture_output=True,
        timeout=90,
    )


def _success(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 0, result.stderr
    return result.stdout


def _setup(home: Path, script: Path, env: dict[str, str], *, noninteractive: bool = False) -> str:
    source = f"""
from pathlib import Path
from mordred_hermes.wizard import setup_cli
home = Path({str(home)!r})
class NoPrompt:
    def __getattr__(self, name):
        def refuse(*a, **kw):
            raise AssertionError("Linux unexpectedly prompted")
        return refuse
kwargs = dict(home=home, root=home / "mordred/vault", platform="linux",
 prompt_io=NoPrompt(), options=setup_cli.SetupOptions(non_interactive={noninteractive!r}))
env_result = setup_cli._resolve_step_env_encryption(**kwargs)
assert env_result.action == "skipped"
result = setup_cli._resolve_step_memory_encryption(**kwargs)
print("RESULT:" + result.action + ":" + result.detail)
"""
    output = _success(_run(home, script, source, env))
    return next(line.removeprefix("RESULT:") for line in output.splitlines() if line.startswith("RESULT:"))


def _all(home: Path, env: dict[str, str], cli: Path) -> subprocess.CompletedProcess[str]:
    # The actual public installed console command, including its parser/dispatch.
    return subprocess.run(
        [str(cli), "encryption", "enable", "all"],
        env=dict(env, HERMES_HOME=str(home)),
        cwd=home,
        text=True,
        capture_output=True,
        timeout=90,
    )


def _snapshot(root: Path) -> dict[str, tuple[int, str | None]]:
    """Opaque inventory: relative names, private modes and content hashes only."""
    if not root.exists():
        return {}
    return {
        str(p.relative_to(root)): (
            stat.S_IMODE(p.stat().st_mode),
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None,
        )
        for p in sorted(root.rglob("*"))
    }


@pytest.mark.parametrize("entrance", ["setup", "all"])
def test_real_tpm_orchestration_and_armed_shape_b_backup(tmp_path, entrance):
    import mordred_hermes
    from mordred_hermes.keyvault._memory_hook import memory_marker_path
    from mordred_hermes.keyvault._memory_key import load_linux_memory_key, memory_key_path
    from mordred_hermes.keyvault._seckey_helper import find_tpmkey_helper
    from mordred_hermes.keyvault.memory_crypto import is_sealed, seal, unseal
    from mordred_hermes.wizard import memory_cli

    assert Path(mordred_hermes.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()), (
        "install the candidate wheel; editable/source evidence is separate"
    )
    assert os.environ.get("HERMES_HOME"), "set an explicitly test-owned parent before interpreter startup"
    assert os.environ.get("MORDRED_ACCEPTANCE_COMMIT"), "record the installed candidate commit"
    assert os.environ.get("MORDRED_LINUX_TPM_PROVIDER"), "record actual provider (e.g. EC2 NitroTPM)"
    assert Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists(), "real TPM device required"
    assert "MORDRED_TPM_TEST" not in os.environ, "emulator gate is forbidden in this acceptance"
    helper = find_tpmkey_helper()
    assert helper, "production TPM helper required"
    cli = Path(sys.executable).with_name("hermes-mordred")
    assert cli.is_file(), "use the candidate's installed Hermes runtime/console command"
    print(
        json.dumps(
            {
                "candidate_commit": os.environ["MORDRED_ACCEPTANCE_COMMIT"],
                "interpreter": sys.executable,
                "python": platform.python_version(),
                "os": platform.platform(),
                "architecture": platform.machine(),
                "provider": os.environ["MORDRED_LINUX_TPM_PROVIDER"],
                "helper": helper,
                "helper_sha256": hashlib.sha256(Path(helper).read_bytes()).hexdigest(),
                "hermes_version": importlib.metadata.version("hermes-agent"),
                "entrance": entrance,
            }
        )
    )
    env = dict(os.environ)
    for name in (
        "HERMES_MEMORY_KEY",
        "MORDRED_TPMKEY_STORE",
        "MORDRED_SEKEY_STORE",
        "PYTHONPATH",
        "PYTHONHOME",
        "HERMES_SAFE_MODE",
        "TCTI",
        "MORDRED_TPM_TEST",
    ):
        env.pop(name, None)
    env["MORDRED_HERMES_RUNTIME_PYTHON"] = sys.executable
    home = tmp_path / entrance
    home.mkdir(mode=0o700)
    script = tmp_path / "hermes"
    (home / "memories").mkdir(mode=0o700)
    path = home / "memories/MEMORY.md"
    path.write_text("synthetic initial memory")
    path.chmod(0o600)
    sentinels = {".env": b"DUMMY_SENTINEL=value\n", "config.yaml": b"dummy: sentinel\n"}
    for name, data in sentinels.items():
        (home / name).write_bytes(data)
    root = home / "mordred/vault"
    if entrance == "setup":
        assert _setup(home, script, env, noninteractive=True).startswith("manual:")
        assert not memory_key_path(home).exists()
        assert _setup(home, script, env).startswith("ran:")
    else:
        output = _success(_all(home, env, cli))
        assert "1 ok, 0 failed, 3 skipped" in output
    assert not root.exists()
    assert not (home / "mordred/keyvault/vault").exists()
    assert memory_marker_path(home).exists()
    wrapped = memory_key_path(home).read_bytes()
    assert len(wrapped) == 127 and stat.S_IMODE(memory_key_path(home).stat().st_mode) == 0o600
    assert is_sealed(path.read_bytes())
    assert sentinels == {name: (home / name).read_bytes() for name in sentinels}
    print(
        _success(
            _run(
                home,
                script,
                _PROVENANCE
                + """
s = memory_tool.MemoryStore(); s.load_from_disk()
assert "synthetic initial memory" in s.memory_entries
assert s.add("memory", "synthetic runtime write")["success"]
""",
                env,
            )
        )
    )
    assert is_sealed(path.read_bytes())
    print(
        _success(
            _run(
                home,
                script,
                _PROVENANCE
                + """
s = memory_tool.MemoryStore(); s.load_from_disk()
assert "synthetic runtime write" in s.memory_entries
""",
                env,
            )
        )
    )
    sealed_source = path.read_bytes()
    if entrance == "setup":
        result = _setup(home, script, env)
        assert result.startswith("done:") and "live TPM access not checked" in result
        assert path.read_bytes() == sealed_source
    assert memory_cli.disable(home=home, root=root, platform="linux") == 0
    plaintext = path.read_bytes()
    assert not is_sealed(plaintext)
    assert b"synthetic runtime write" in plaintext
    assert _setup(home, script, env).startswith("done:paused")
    assert path.read_bytes() == plaintext
    # Explicit enable-all reverses opt-out while reusing the exact wrapped key.
    assert "1 ok, 0 failed, 3 skipped" in _success(_all(home, env, cli))
    assert memory_key_path(home).read_bytes() == wrapped
    assert is_sealed(path.read_bytes())
    sealed_source = path.read_bytes()
    prior = home / "memories/MEMORY.md.bak.prior"
    prior.write_bytes(seal(b"synthetic prior backup", key=load_linux_memory_key(home=home), name=prior.name))
    prior.chmod(0o600)
    native = home / "mordred/keyvault/tpm"
    custody = _snapshot(native)
    assert custody, "managed TPM native inventory must be nonempty before preservation checks"
    marker = memory_marker_path(home).read_bytes()
    prior_blob = prior.read_bytes()
    external = b"x" * 100
    path.write_bytes(external)
    backup_output = _success(
        _run(
            home,
            script,
            _PROVENANCE
            + """
s = memory_tool.MemoryStore(memory_char_limit=40)
backup = s._detect_external_drift("memory")
assert backup is not None
print("BACKUP:" + backup)
""",
            env,
        )
    )
    print(backup_output)
    backup = Path(
        next(line.removeprefix("BACKUP:") for line in backup_output.splitlines() if line.startswith("BACKUP:"))
    )
    assert backup.parent.resolve() == path.parent.resolve()
    assert backup.name.startswith("MEMORY.md.bak.") and backup != prior
    assert is_sealed(backup.read_bytes())
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    decoded = unseal(backup.read_bytes(), key=load_linux_memory_key(home=home), name=backup.name)
    assert decoded == external
    assert path.read_bytes() == external and prior.read_bytes() == prior_blob
    assert memory_key_path(home).read_bytes() == wrapped and memory_marker_path(home).read_bytes() == marker
    assert _snapshot(native) == custody
    memories = _snapshot(path.parent)
    wrapped_mode = stat.S_IMODE(memory_key_path(home).stat().st_mode)
    try:
        for damage in ("corrupt", "missing"):
            if damage == "corrupt":
                memory_key_path(home).write_bytes(b"invalid wrapper")
            else:
                memory_key_path(home).unlink()
            damaged = memory_key_path(home).read_bytes() if memory_key_path(home).exists() else None
            _success(
                _run(
                    home,
                    script,
                    _PROVENANCE
                    + """
from mordred_hermes.keyvault._memory_hook import MemoryEncryptionUnavailable
s = memory_tool.MemoryStore(memory_char_limit=40)
try:
    s._detect_external_drift("memory")
except MemoryEncryptionUnavailable:
    pass
else:
    raise AssertionError("armed plaintext backup did not refuse unavailable custody")
""",
                    env,
                )
            )
            if entrance == "setup":
                assert _setup(home, script, env).startswith("failed:")
            else:
                result = _all(home, env, cli)
                assert result.returncode == 1
                assert "0 ok, 1 failed, 3 skipped" in result.stdout
            assert _snapshot(path.parent) == memories
            assert _snapshot(native) == custody
            assert memory_marker_path(home).read_bytes() == marker
            assert (memory_key_path(home).read_bytes() if memory_key_path(home).exists() else None) == damaged
            memory_key_path(home).write_bytes(wrapped)
            memory_key_path(home).chmod(wrapped_mode)
    finally:
        # Restore even on failure. A failed assertion deliberately retains the
        # synthetic home for inspection rather than deleting uncertain custody.
        memory_key_path(home).write_bytes(wrapped)
        memory_key_path(home).chmod(wrapped_mode)
    decoded = unseal(backup.read_bytes(), key=load_linux_memory_key(home=home), name=backup.name)
    assert decoded == external
    path.write_bytes(sealed_source)
    _success(
        _run(
            home,
            script,
            _PROVENANCE
            + """
s = memory_tool.MemoryStore(); s.load_from_disk()
assert "synthetic runtime write" in s.memory_entries
""",
            env,
        )
    )
    assert memory_cli.disable(home=home, root=root, platform="linux") == 0
    assert not is_sealed(path.read_bytes()) and b"synthetic runtime write" in path.read_bytes()
    assert memory_cli.purge(home=home, root=root, platform="linux") == 0
    assert not memory_key_path(home).exists()
    assert not memory_marker_path(home).exists()
    assert not _snapshot(native)
