"""Windows Telegram guard consumes C6 checked memory without native operations."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._private_fs import PrivateFSError
from mordred_hermes.extension.telegram import hermes_tools, memory_guard, service
from mordred_hermes.extension.telegram.ask import AskRequest
from mordred_hermes.keyvault import _seckey_helper, _windows_proof, wrap
from mordred_hermes.wizard import _windows_memory, keyvault_windows_cli, memory_cli
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_lifecycle import ORIGINALS, put
from tests.test_windows_memory_proof import INJECTION
from tests.test_windows_memory_proof import installed_runtime as installed_runtime
from tests.test_windows_memory_proof import proof_env as proof_env
from tests.test_wizard_windows_memory import win as win

pytestmark = pytest.mark.memory_plain


def forbid_native(monkeypatch, env):
    class ForbiddenOperation(BaseException):
        pass

    def tripwire(*args, **kwargs):
        raise ForbiddenOperation("guard reached native, enrollment, proof or process operation")

    monkeypatch.setattr(env.custody, "windows_backend", tripwire)
    monkeypatch.setattr(env.custody.WindowsCustodySession, "enroll_memory", tripwire)
    monkeypatch.setattr(wrap, "unwrap_dek", tripwire)
    monkeypatch.setattr(_windows_proof, "prove_windows_memory_runtime", tripwire)
    monkeypatch.setattr(subprocess, "Popen", tripwire)
    monkeypatch.setattr(subprocess, "run", tripwire)


@pytest.fixture
def windows_guard(win, monkeypatch):
    # Do not mutate global sys.platform: checked filesystem uses the real host.
    monkeypatch.setattr(memory_guard, "sys", SimpleNamespace(platform="win32"))
    return win


def arm(env, populated):
    if populated:
        for name, data in ORIGINALS.items():
            put(env.home, "memories", name, data)
    assert memory_cli.enable(home=env.home, root=env.home / "vault", platform="win32") == 0


@pytest.mark.parametrize("populated", [False, True])
@pytest.mark.parametrize("explicit_home", [False, True])
def test_armed_checked_memory_permits_telegram_without_native_operations(
    windows_guard, monkeypatch, populated, explicit_home
):
    env = windows_guard
    arm(env, populated)
    forbid_native(monkeypatch, env)
    home = env.home if explicit_home else None
    assert memory_guard.memory_encryption_active(home)
    memory_guard.require_memory_encryption(home)


@pytest.mark.parametrize(
    "state", ["unmanaged", "enrolled-only", "opted-out", "broken-seal", "staging", "plaintext-drift", "helper-missing"]
)
def test_unsafe_checked_memory_refuses_telegram(windows_guard, monkeypatch, state):
    env = windows_guard
    if state == "unmanaged":
        pass
    elif state == "enrolled-only":
        assert keyvault_windows_cli.native_init(home=env.home) == 0
    else:
        arm(env, True)
        if state == "opted-out":
            assert memory_cli.disable(home=env.home, root=env.home / "vault", platform="win32") == 0
        elif state == "broken-seal":
            put(env.home, "memories", "BROKEN.md", b"HERMES-MEMORY-ENC-v1\nnot-a-seal")
        elif state == "staging":
            put(env.home, "memories", ".mordred-memory-open.interrupted", b"staged plaintext")
        elif state == "plaintext-drift":
            put(env.home, "memories", "NEW.md", b"outside hook")
        elif state == "helper-missing":
            monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    forbid_native(monkeypatch, env)
    assert not memory_guard.memory_encryption_active(env.home)
    with pytest.raises(memory_guard.MemoryEncryptionRequired) as exc:
        memory_guard.require_memory_encryption(env.home)
    assert exc.value.code == "memory_encryption_required"


@pytest.mark.parametrize("failure", [OSError("unreadable"), RuntimeError("scan failed")])
def test_unreadable_windows_scan_fails_closed(windows_guard, monkeypatch, failure):
    arm(windows_guard, False)

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(_windows_memory, "observe", fail)
    assert not memory_guard.memory_encryption_active(windows_guard.home)
    with pytest.raises(memory_guard.MemoryEncryptionRequired) as exc:
        memory_guard.require_memory_encryption(windows_guard.home)
    assert exc.value.code == "memory_encryption_required"


@contextmanager
def held_canonical_lock(env):
    """Another interpreter owns the real canonical lock until the parent releases it."""
    ready, release = env.home.parent / "ready", env.home.parent / "release"
    code = """
import importlib.util, os, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('_inject', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.install()
from mordred_hermes._config_io import CanonicalPaths, canonical_session
with canonical_session(CanonicalPaths(Path(os.environ['HERMES_HOME'])), scope='policy'):
    Path(sys.argv[2]).touch()
    until = time.monotonic() + 30
    while not Path(sys.argv[3]).exists() and time.monotonic() < until:
        time.sleep(0.01)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(INJECTION), str(ready), str(release)],
        env=os.environ | {"HERMES_HOME": str(env.home)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        until = time.monotonic() + 15
        while not ready.exists() and child.poll() is None and time.monotonic() < until:
            time.sleep(0.01)
        assert ready.exists(), "canonical lock child failed to become ready"
        yield
    finally:
        release.touch()
        out, err = child.communicate(timeout=15)
        assert child.returncode == 0, (out, err)


def test_cross_process_contention_retains_busy_code_before_telegram_access(windows_guard, monkeypatch):
    env = windows_guard
    arm(env, True)

    def forbidden(*args, **kwargs):
        raise AssertionError("guard allowed secret, archive or network access")

    svc = service.TelegramService(
        secret_store=SimpleNamespace(load=forbidden, flags=forbidden),
        installed=lambda: True,
        client_factory=forbidden,
        http_session_factory=forbidden,
    )
    monkeypatch.setattr(svc, "_archive", forbidden)
    monkeypatch.setattr(hermes_tools, "_service", lambda: svc)

    async def ask():
        async for _ in svc.ask(AskRequest(question="q"), forbidden):
            pass

    with held_canonical_lock(env), monkeypatch.context() as patch:
        forbid_native(patch, env)
        assert not memory_guard.memory_encryption_active(env.home)
        for call in (svc.start_sync, svc.dialogs, ask):
            with pytest.raises(memory_guard.MemoryEncryptionRequired) as exc:
                asyncio.run(call())
            assert exc.value.code == "custody_busy"
            assert service.error_code(exc.value, "fallback") == "custody_busy"
        agent = SimpleNamespace(model="local", base_url="http://127.0.0.1:11434/v1")
        for tool, args in ((hermes_tools.telegram_chats, {}), (hermes_tools.telegram_ask, {"question": "q"})):
            assert json.loads(asyncio.run(tool(args, parent_agent=agent))) == {"error": "custody_busy"}
        assert not svc.syncing and not svc._sync_starting
    memory_guard.require_memory_encryption(env.home)


def test_canonical_release_failure_cannot_permit_telegram(windows_guard, monkeypatch):
    arm(windows_guard, False)
    real = cio.canonical_session
    calls = 0

    @contextmanager
    def failing_release(*args, **kwargs):
        nonlocal calls
        calls += 1
        outer = calls == 1
        with real(*args, **kwargs) as session:
            yield session
        if outer:
            raise PrivateFSError("unsafe", "canonical_lock")

    monkeypatch.setattr(cio, "canonical_session", failing_release)
    assert not memory_guard.memory_encryption_active(windows_guard.home)
    calls = 0
    with pytest.raises(memory_guard.MemoryEncryptionRequired) as exc:
        memory_guard.require_memory_encryption(windows_guard.home)
    assert exc.value.code == "memory_encryption_required"


def test_each_public_guard_scans_memory_once(windows_guard, monkeypatch):
    env = windows_guard
    arm(env, True)
    real = _windows_memory.observe
    calls = []

    def observed(home, *, blocking):
        calls.append((home, blocking))
        return real(home, blocking=blocking)

    monkeypatch.setattr(_windows_memory, "observe", observed)
    assert memory_guard.memory_encryption_active(env.home)
    assert calls == [(env.home, False)]
    calls.clear()
    memory_guard.require_memory_encryption(env.home)
    assert calls == [(env.home, False)]
