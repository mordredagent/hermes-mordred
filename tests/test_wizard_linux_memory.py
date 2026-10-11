"""Linux lifecycle uses TPM custody without enrolling an env vault."""

import pytest

from mordred_hermes.keyvault import _memory_key as mk
from mordred_hermes.keyvault import _runtime_probe
from mordred_hermes.keyvault._memory_hook import memory_marker_path
from mordred_hermes.keyvault.memory_crypto import is_sealed
from mordred_hermes.wizard import _windows_gates, encryption_cli, memory_cli
from tests._keyvault_fakes import FakeBackend


@pytest.fixture
def linux(tmp_path, monkeypatch):
    backend = FakeBackend()
    monkeypatch.setattr(mk, "linux_memory_backend", lambda home: backend)
    monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, "A"))
    monkeypatch.setattr(_runtime_probe, "runtime_memory_encryption_available", lambda **kw: (True, "A"))
    monkeypatch.setattr(_runtime_probe, "runtime_memory_key_available", lambda **kw: (True, "verified"))
    monkeypatch.setattr(_runtime_probe, "discover_running_gateway_runtimes", lambda **kw: [])
    monkeypatch.setattr(memory_cli, "_warn_gateways", lambda *a, **kw: None)

    def forbidden(**kw):
        pytest.fail("Linux must not open a file vault")

    monkeypatch.setattr(memory_cli, "_ensure_key", forbidden)
    (tmp_path / "memories").mkdir()
    (tmp_path / "memories" / "MEMORY.md").write_text("synthetic private memory")
    return tmp_path, backend


def test_linux_disable_reenable_and_purge(linux):
    home, backend = linux
    root = home / "mordred" / "keyvault" / "vault"
    path = home / "memories" / "MEMORY.md"
    assert memory_cli.enable(home=home, root=root, platform="linux") == 0
    assert is_sealed(path.read_bytes())
    key = mk.load_linux_memory_key(home=home)
    assert not root.exists()
    assert memory_cli.disable(home=home, root=root) == 0
    assert path.read_text() == "synthetic private memory"
    assert memory_cli.enable(home=home, root=root, platform="linux") == 0
    assert mk.load_linux_memory_key(home=home) == key
    assert memory_cli.purge(home=home, root=root) == 0
    assert not mk.memory_key_path(home).exists()
    assert not backend._keys
    assert path.read_text() == "synthetic private memory"


def test_key_probe_failure_preserves_files(linux, monkeypatch):
    home, _ = linux
    monkeypatch.setattr(_runtime_probe, "runtime_memory_key_available", lambda **kw: (False, "unavailable"))
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 1
    assert not memory_marker_path(home).exists()
    assert (home / "memories" / "MEMORY.md").read_text() == "synthetic private memory"


def test_status_never_unwraps_or_enables_env(linux, monkeypatch):
    home, backend = linux
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    backend._keys.clear()
    status = encryption_cli.memory_status(home=home, platform="linux")
    assert status.active
    assert "TPM" in status.detail
    mk.memory_key_path(home).write_bytes(b"broken")
    assert not encryption_cli.memory_status(home=home, platform="linux").active


def test_disable_preserves_ciphertext_without_tpm(linux):
    home, backend = linux
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    path = home / "memories" / "MEMORY.md"
    blob = path.read_bytes()
    backend._keys.clear()
    assert memory_cli.disable(home=home, root=home / "vault") == 1
    assert path.read_bytes() == blob
    assert memory_marker_path(home).exists()


def test_uninstall_linux_memory_does_not_require_file_vault(linux):
    from types import SimpleNamespace

    from mordred_hermes.wizard import uninstall_cli

    home, _ = linux
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    ctx = SimpleNamespace(home=home, vault_root=home / "vault", platform="linux")
    restores = uninstall_cli._restores(ctx)
    memory = next(r for r in restores if r.target == "memory")
    assert memory.needs_vault is False


def test_enable_refuses_live_gateway_before_provisioning(linux, monkeypatch):
    from pathlib import Path

    from mordred_hermes.keyvault._runtime_probe import GatewayRuntime

    home, _ = linux
    monkeypatch.setattr(
        _runtime_probe,
        "discover_running_gateway_runtimes",
        lambda **kw: [GatewayRuntime(pid=999, python=Path("/old/python"))],
    )
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 1
    assert not mk.memory_key_path(home).exists()
    assert not memory_marker_path(home).exists()


def test_runtime_write_waits_for_purge_lock(linux, monkeypatch):
    """An in-flight write may not reseal after the only key is deleted."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _memory_hook as hook
    from tests._helpers import PlatformSys

    home, _ = linux
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    path = home / "memories/MEMORY.md"
    monkeypatch.setattr(hook, "sys", PlatformSys("linux"))
    started = Event()

    def original(path, entries):
        started.set()
        path.write_text("\n".join(entries))

    store = SimpleNamespace(_write_file=original)
    cfg = hook._HookConfig(environ={}, delimiter="\n", home_factory=lambda: home)
    hook._wrap_write_file(store, cfg)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with mk.memory_key_lock(home):
            future = pool.submit(store._write_file, path, ["concurrent update"])
            assert not started.wait(0.1), "write escaped the lifecycle lock"
            assert memory_cli.purge(home=home, root=home / "vault") == 0
        future.result(timeout=5)
    assert path.read_text() == "concurrent update"
    assert not mk.memory_key_path(home).exists()


def test_managed_reenable_ignores_invalid_ambient_key(linux, monkeypatch):
    """Once TPM custody exists, a stale shell variable cannot block re-enable."""
    home, _ = linux
    root = home / "vault"
    assert memory_cli.enable(home=home, root=root, platform="linux") == 0
    wrapped = mk.memory_key_path(home).read_bytes()
    assert memory_cli.disable(home=home, root=root) == 0
    monkeypatch.setenv("HERMES_MEMORY_KEY", "obsolete-invalid-key")
    assert memory_cli.enable(home=home, root=root, platform="linux") == 0
    assert mk.memory_key_path(home).read_bytes() == wrapped
    assert is_sealed((home / "memories/MEMORY.md").read_bytes())


@pytest.mark.parametrize("operation", ["enable", "disable", "purge"])
@pytest.mark.parametrize("unreadable", ["directory", "file"])
def test_inaccessible_memory_directory_preserves_key_and_ciphertext(linux, operation, unreadable):
    """A failed directory scan must never be mistaken for no encrypted files."""
    import os

    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    home, backend = linux
    root = home / "vault"
    assert memory_cli.enable(home=home, root=root, platform="linux") == 0
    path = home / "memories/MEMORY.md"
    ciphertext = path.read_bytes()
    wrapped = mk.memory_key_path(home).read_bytes()
    keys = set(backend._keys)
    target = path.parent if unreadable == "directory" else path
    target.chmod(0)
    try:
        kwargs = {"platform": "linux"} if operation == "enable" else {}
        assert getattr(memory_cli, operation)(home=home, root=root, **kwargs) == 1
        assert mk.memory_key_path(home).read_bytes() == wrapped
        assert set(backend._keys) == keys
        assert memory_marker_path(home).exists()
    finally:
        target.chmod(0o700 if unreadable == "directory" else 0o600)
    assert path.read_bytes() == ciphertext


def test_keyvault_reset_refuses_while_tpm_memory_key_is_retained(linux, capsys):
    from mordred_hermes.keyvault import _storage
    from mordred_hermes.wizard import keyvault_cli

    home, backend = linux
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    native = root / "tpm/memory-key.blob"
    native.parent.mkdir(mode=0o700)
    native.write_bytes(b"synthetic opaque TPM material")
    wrapped = mk.memory_key_path(home).read_bytes()
    assert keyvault_cli.reset_keyvault(home=home, backend=backend, assume_yes=True) == 1
    assert native.read_bytes() == b"synthetic opaque TPM material"
    assert mk.memory_key_path(home).read_bytes() == wrapped
    assert "encryption purge memory" in capsys.readouterr().err
    assert memory_cli.purge(home=home, root=home / "vault") == 0
    assert keyvault_cli.reset_keyvault(home=home, backend=backend, assume_yes=True) == 0
    assert not root.exists()


def test_uninstall_data_purge_removes_memory_custody_before_keyvault(linux):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _storage
    from mordred_hermes.wizard import uninstall_cli

    home, backend = linux
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    _storage.ensure_layout(_storage.resolve_keyvault_dir(home))
    assert memory_cli.disable(home=home, root=home / "vault") == 0
    ctx = SimpleNamespace(
        home=home,
        vault_root=home / "vault",
        backend=backend,
        platform="linux",
        keyvault_reset=None,
        telegram_forget=None,
    )
    assert uninstall_cli._purge_data(ctx, SimpleNamespace(telegram_configured=False)) == 0
    assert not mk.memory_key_path(home).exists()
    assert not backend._keys
    assert (home / "memories/MEMORY.md").read_text() == "synthetic private memory"


def test_reset_waits_for_concurrent_memory_provisioning(linux, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from mordred_hermes.keyvault import _storage
    from mordred_hermes.wizard import keyvault_cli
    from tests._helpers import PlatformSys

    home, backend = linux
    (home / "mordred").mkdir(mode=0o700)
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    monkeypatch.setattr(keyvault_cli, "sys", PlatformSys("linux"))
    started = Event()
    finished = Event()

    def reset():
        started.set()
        try:
            return keyvault_cli.reset_keyvault(home=home, backend=backend, assume_yes=True)
        finally:
            finished.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with mk.memory_key_lock(home):
            future = pool.submit(reset)
            assert started.wait(2)
            assert not finished.wait(0.1)
            key = mk.ensure_linux_memory_key(home=home, backend=backend)
        assert future.result(timeout=5) == 1
    assert root.exists()
    assert mk.load_linux_memory_key(home=home, backend=backend) == key


def test_status_refuses_unreadable_memory_tree(linux):
    import os

    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    home, _ = linux
    assert memory_cli.enable(home=home, root=home / "vault", platform="linux") == 0
    memories = home / "memories"
    memories.chmod(0)
    try:
        status = encryption_cli.memory_status(home=home, platform="linux")
        assert not status.active
        assert "unreadable" in status.detail
        assert "written by this runtime are plaintext" not in status.detail
    finally:
        memories.chmod(0o700)


class NoPrompt:
    def __getattr__(self, name):
        return lambda *a, **kw: pytest.fail(f"Linux memory must not prompt: {name}")


def setup_memory(home, **kwargs):
    from mordred_hermes.wizard import setup_cli

    return setup_cli._resolve_step_memory_encryption(
        home=home,
        root=home / "mordred/vault",
        platform="linux",
        prompt_io=NoPrompt(),
        options=kwargs.pop("options", setup_cli.SetupOptions()),
        **kwargs,
    )


@pytest.fixture
def orchestration(linux, monkeypatch):
    from mordred_hermes.wizard import setup_cli

    home, backend = linux
    monkeypatch.setenv("HERMES_HOME", str(home))
    # Exercise selected Linux on a Unix host seam, independently of the runner.
    monkeypatch.setattr(_windows_gates, "host_platform", lambda: "darwin")
    monkeypatch.setattr(encryption_cli, "_env_target_ready", lambda **kw: pytest.fail("Linux checked env readiness"))
    monkeypatch.setattr(setup_cli, "_env_target_ready", lambda **kw: pytest.fail("Linux checked env readiness"))
    for name, content in ((".env", "DUMMY_SENTINEL=value\n"), ("config.yaml", "dummy: sentinel\n")):
        (home / name).write_text(content)
    return home, backend


@pytest.mark.parametrize("entrance", ["setup", "all"])
def test_linux_orchestration_seals_without_file_vault(orchestration, entrance, capsys):
    home, _ = orchestration
    sentinels = {name: (home / name).read_bytes() for name in (".env", "config.yaml")}
    if entrance == "setup":
        assert setup_memory(home).action == "ran"
    else:
        assert encryption_cli._dispatch_all("enable", platform="linux") == 0
        assert "1 ok, 0 failed, 3 skipped" in capsys.readouterr().out
    assert is_sealed((home / "memories/MEMORY.md").read_bytes())
    assert memory_marker_path(home).exists()
    assert len(mk.memory_key_path(home).read_bytes()) == 127
    assert not (home / "mordred/vault").exists()
    assert not (home / "mordred/keyvault/vault").exists()
    assert sentinels == {name: (home / name).read_bytes() for name in sentinels}


def test_linux_setup_env_skips_before_probe_or_enrollment(orchestration, monkeypatch):
    from mordred_hermes.wizard import setup_cli

    home, _ = orchestration
    monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: pytest.fail("env probe reached"))
    result = setup_cli._resolve_step_env_encryption(
        home=home,
        root=home / "mordred/vault",
        platform="linux",
        prompt_io=NoPrompt(),
        options=setup_cli.SetupOptions(),
    )
    assert result.action == "skipped"
    assert (home / ".env").read_text() == "DUMMY_SENTINEL=value\n"
    assert not (home / "mordred/vault").exists()


def test_linux_setup_readiness_pause_and_explicit_reenable(orchestration, monkeypatch):
    from mordred_hermes.wizard import setup_cli

    home, backend = orchestration
    assert setup_memory(home).action == "ran"
    wrapped = mk.memory_key_path(home).read_bytes()
    path = home / "memories/MEMORY.md"
    sealed = path.read_bytes()
    with monkeypatch.context() as mp:
        mp.setattr(mk, "linux_memory_backend", lambda *a, **kw: pytest.fail("readiness touched TPM"))
        mp.setattr(_runtime_probe, "runtime_memory_key_available", lambda **kw: pytest.fail("readiness probed runtime"))
        result = setup_memory(home)
        assert result.action == "done"
        assert "live TPM access not checked" in result.detail
        assert path.read_bytes() == sealed
    path.write_text("synthetic external drift")
    assert not setup_cli._probe_memory_encryption(home=home, platform="linux")[0]
    assert setup_memory(home).action == "ran"
    assert is_sealed(path.read_bytes())
    assert memory_cli.disable(home=home, root=home / "mordred/vault", platform="linux") == 0
    paused = path.read_bytes()
    with monkeypatch.context() as mp:
        mp.setattr(encryption_cli, "memory_status", lambda **kw: pytest.fail("optout must precede status"))
        assert setup_memory(home).action == "done"
    assert path.read_bytes() == paused
    assert encryption_cli._dispatch_all("enable", platform="linux") == 0
    assert mk.memory_key_path(home).read_bytes() == wrapped
    assert is_sealed(path.read_bytes())
    assert len(backend._keys) == 1


@pytest.mark.parametrize("entrance", ["setup", "all"])
@pytest.mark.parametrize("failure", ["preproof", "postproof", "missing", "corrupt", "unknown"])
def test_linux_orchestration_refusal_preserves_state(orchestration, monkeypatch, entrance, failure, capsys):
    from mordred_hermes.wizard import setup_cli

    home, backend = orchestration
    path = home / "memories/MEMORY.md"
    if failure in ("missing", "corrupt", "unknown"):
        assert memory_cli.enable(home=home, root=home / "mordred/vault", platform="linux") == 0
        if failure == "missing":
            mk.memory_key_path(home).unlink()
        elif failure == "corrupt":
            mk.memory_key_path(home).write_bytes(b"invalid wrapper")
        else:
            backend._keys.clear()
    else:
        name = "runtime_memory_encryption_available" if failure == "preproof" else "runtime_memory_key_available"
        monkeypatch.setattr(_runtime_probe, name, lambda **kw: (False, "unavailable"))
    before = path.read_bytes()
    marker = memory_marker_path(home).exists()
    wrapped = mk.memory_key_path(home).read_bytes() if mk.memory_key_path(home).exists() else None
    keys = dict(backend._keys)
    assert not setup_cli._probe_memory_encryption(home=home, platform="linux")[0] or failure == "unknown"
    # Structural readiness cannot detect an otherwise valid wrapper whose native key is lost.
    if entrance == "setup" and failure == "unknown":
        path.write_text("synthetic drift requiring live unwrap")
        before = path.read_bytes()
    if entrance == "setup":
        assert setup_memory(home).action == "failed"
    else:
        assert encryption_cli._dispatch_all("enable", platform="linux") == 1
        assert "0 ok, 1 failed, 3 skipped" in capsys.readouterr().out
    assert path.read_bytes() == before
    assert memory_marker_path(home).exists() == marker
    if failure == "postproof":
        assert mk.memory_key_path(home).exists()  # permitted inert custody after failed installed-runtime proof
    else:
        assert (mk.memory_key_path(home).read_bytes() if mk.memory_key_path(home).exists() else None) == wrapped
        assert backend._keys == keys


def test_linux_noninteractive_and_unreadable_readiness(orchestration, monkeypatch):
    from mordred_hermes.wizard import setup_cli

    home, _ = orchestration
    result = setup_memory(home, options=setup_cli.SetupOptions(non_interactive=True))
    assert result.action == "manual"
    assert "TPM" in result.detail
    assert not mk.memory_key_path(home).exists()
    assert setup_memory(home).action == "ran"
    monkeypatch.setattr(mk, "linux_memory_files", lambda home: (_ for _ in ()).throw(OSError("unreadable")))
    assert not setup_cli._probe_memory_encryption(home=home, platform="linux")[0]
    assert setup_memory(home, options=setup_cli.SetupOptions(non_interactive=True)).action == "manual"


@pytest.mark.parametrize("force", [False, True])
def test_linux_enable_all_without_seam_skips_even_with_force(orchestration, monkeypatch, force, capsys):
    home, _ = orchestration
    monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (False, "no seam"))
    assert encryption_cli._dispatch_all("enable", platform="linux", force_runtime_unverified=force) == 0
    assert "0 ok, 0 failed, 4 skipped" in capsys.readouterr().out
    assert not mk.memory_key_path(home).exists()


def test_linux_enable_all_force_does_not_bypass_key_integrity(orchestration, monkeypatch):
    home, _ = orchestration
    assert memory_cli.enable(home=home, root=home / "mordred/vault", platform="linux") == 0
    mk.memory_key_path(home).write_bytes(b"corrupt")
    sealed = (home / "memories/MEMORY.md").read_bytes()
    monkeypatch.setattr(_runtime_probe, "runtime_memory_encryption_available", lambda **kw: (False, "unavailable"))
    assert encryption_cli._dispatch_all("enable", platform="linux", force_runtime_unverified=True) == 1
    assert mk.memory_key_path(home).read_bytes() == b"corrupt"
    assert (home / "memories/MEMORY.md").read_bytes() == sealed


def test_linux_force_reaches_engine_with_runtime_unavailable(orchestration, monkeypatch):
    home, _ = orchestration
    monkeypatch.setattr(_runtime_probe, "runtime_memory_encryption_available", lambda **kw: (False, "unavailable"))
    monkeypatch.setattr(_runtime_probe, "runtime_memory_key_available", lambda **kw: (False, "unavailable"))
    assert encryption_cli._dispatch_all("enable", platform="linux", force_runtime_unverified=True) == 0
    assert is_sealed((home / "memories/MEMORY.md").read_bytes())
    assert memory_marker_path(home).exists()


@pytest.mark.parametrize("error,action", [(OSError("disk unavailable"), "failed"), (pytest.param("abort", "manual"))])
def test_linux_setup_reports_engine_oserror(orchestration, monkeypatch, error, action):
    from mordred_hermes.wizard import setup_cli

    home, _ = orchestration

    def fail(**kw):
        from mordred_hermes.wizard._prompt_io import NonInteractiveAbort

        raise NonInteractiveAbort("aborted") if error == "abort" else error

    monkeypatch.setattr(setup_cli, "_run_memory_encryption", fail)
    assert setup_memory(home).action == action
