"""Each supported Windows memory seam must avoid upstream raw I/O."""

import os
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import _memory_hook as hook
from mordred_hermes.keyvault.memory_crypto import is_sealed, seal, unseal
from tests.test_keyvault_memory_hook import ENTRY_DELIMITER, _fake_module
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_storage import enroll, mark, put
from tests.test_windows_memory_storage import memory as memory

ROOT = Path(__file__).resolve().parents[1]


class Win32Sys:
    """``sys`` as the hook sees it on Windows; every other attribute stays live."""

    platform = "win32"

    def __getattr__(self, name):
        return getattr(sys, name)


@pytest.fixture
def windows(memory, monkeypatch):
    monkeypatch.setattr(hook, "sys", Win32Sys())
    return memory


def module_for(home, shape):
    module = _fake_module(shape, home / "memories")
    store = module.MemoryStore

    def _write_file(path, entries):
        raise AssertionError("upstream raw write called")

    def _read_raw_checked(path):
        raise AssertionError("upstream raw read called")

    def _read_file(path):
        raise AssertionError("upstream raw read called")

    store._write_file = staticmethod(_write_file)
    if shape == "A":
        store._read_raw_checked = staticmethod(_read_raw_checked)
    else:
        store._read_file = staticmethod(_read_file)
    assert hook.install_memory_hook(home=home, memory_tool_module=module, environ={})
    return module


@pytest.mark.parametrize("shape", ["A", "B", "C"])
def test_checked_unmanaged_read_write_each_seam(windows, shape):
    _, home, backend = windows
    module = module_for(home, shape)
    path = home / "memories" / "MEMORY.md"
    assert module.MemoryStore._read_file(path) == []
    module.MemoryStore._write_file(path, [" alpha ", "beta"])
    assert module.MemoryStore._read_file(path) == ["alpha", "beta"]
    assert path.read_text() == " alpha \n§\nbeta"
    assert not backend.calls


@pytest.mark.parametrize("shape", ["A", "B", "C"])
def test_managed_read_write_and_optout_each_seam(windows, shape):
    _, home, _ = windows
    key, _ = enroll(windows)
    mark(home)
    module = module_for(home, shape)
    path = home / "memories" / "MEMORY.md"
    module.MemoryStore._write_file(path, ["alpha", "beta"])
    assert module.MemoryStore._read_file(path) == ["alpha", "beta"]
    assert is_sealed(path.read_bytes())
    mark(home, "memory-vault.optout")
    module.MemoryStore._write_file(path, ["gamma"])
    opened = unseal(path.read_bytes(), key=key, name=path.name) == b"gamma"
    assert opened, "opt-out write did not stay sealed"


@pytest.mark.parametrize("shape", ["A", "B", "C"])
def test_unsafe_raw_read_refuses_instead_of_missing(windows, shape):
    _, home, _ = windows
    put(home, "MEMORY.md", b"data")
    path = home / "memories" / "MEMORY.md"
    path.unlink()
    path.mkdir(mode=0o700)
    module = module_for(home, shape)
    with pytest.raises(hook.MemoryEncryptionUnavailable):
        module.MemoryStore._read_file(path)


@pytest.mark.parametrize("shape", ["A", "B"])
def test_drift_backup_authenticates_and_collision_cannot_overwrite(windows, shape, monkeypatch):
    _, home, _ = windows
    key, _ = enroll(windows)
    mark(home)
    raw = "abcdef"
    put(home, "MEMORY.md", seal(raw.encode(), key=key, name="MEMORY.md"))
    module = module_for(home, shape)
    store = module.MemoryStore(memory_char_limit=1)
    monkeypatch.setattr(hook.time, "time", lambda: 42)
    args = ("memory", raw) if shape == "A" else ("memory",)
    backup = store._detect_external_drift(*args)
    path = home / "memories" / "MEMORY.md.bak.42"
    assert backup == str(path)
    opened = unseal(path.read_bytes(), key=key, name=path.name) == b"abcdef"
    assert opened, "drift backup does not authenticate"
    before = path.read_bytes()
    assert "BACKUP FAILED" in store._detect_external_drift(*args)
    assert path.read_bytes() == before


def test_shape_a_stale_snapshot_refuses(windows):
    _, home, _ = windows
    key, _ = enroll(windows)
    put(home, "MEMORY.md", seal(b"new", key=key, name="MEMORY.md"))
    module = module_for(home, "A")
    with pytest.raises(hook.MemoryEncryptionUnavailable):
        module.MemoryStore()._detect_external_drift("memory", "old")
    assert not list((home / "memories").glob("*.bak.*"))


def test_windows_journey_refuses_raw_memory_but_preserves_skills(windows):
    _, home, _ = windows
    from types import ModuleType

    module = ModuleType("journey_fixture")
    module.parse_node_kind = lambda value: "memory" if value.startswith("memory:") else "skill"
    module._memories_dir = lambda: home / "memories"
    module._MEMORY_FILES = {"memory": "MEMORY.md", "profile": "USER.md"}

    def delete_node(node_id):
        if node_id.startswith("memory:"):
            raise AssertionError("raw journey memory mutation")
        return {"ok": True}

    def edit_node(node_id, content):
        return delete_node(node_id)

    module.delete_node = delete_node
    module.edit_node = edit_node
    assert hook.install_journey_guard(module, home=home)
    assert module.delete_node("skill-name") == {"ok": True}
    assert module.edit_node("memory:memory:0", "new")["ok"] is False
    module._MEMORY_FILES["memory"] = "../../other.md"
    with pytest.raises((hook.MemoryEncryptionUnavailable, PrivateFSError)):
        module.delete_node("memory:memory:0")


def test_managed_unsupported_seam_refuses_even_safe_mode_optout(windows):
    _, home, _ = windows
    enroll(windows)
    mark(home, "memory-vault.optout")
    module = SimpleNamespace(MemoryStore=object, ENTRY_DELIMITER=ENTRY_DELIMITER)
    with pytest.raises(SystemExit):
        hook.install_memory_hook(home=home, memory_tool_module=module, environ={"HERMES_SAFE_MODE": "1"})


def test_checked_session_diagnosis_reports_invalid_utf8(windows, capsys):
    _, home, _ = windows
    put(home, "MEMORY.md", b"bad\xff")
    assert hook.warn_when_memory_is_locked(home=home)
    assert "Windows memory" in capsys.readouterr().err


def test_checked_session_diagnosis_reports_denial(windows, monkeypatch, capsys):
    from mordred_hermes.keyvault import _memory_storage as storage

    _, home, _ = windows
    put(home, "MEMORY.md", b"plain")
    optional = storage.open_optional_confidential_directory
    denied = PrivateFSError("access_denied", "read")

    class DeniedTransaction:
        def __init__(self, tx):
            self.tx = tx

        def __getattr__(self, name):
            return getattr(self.tx, name)

        def read_bytes(self, name, **kwargs):
            raise denied

    class DeniedDirectory:
        def __init__(self, directory):
            self.directory = directory

        def __getattr__(self, name):
            return getattr(self.directory, name)

        @contextmanager
        def transaction(self):
            with self.directory.transaction() as tx:
                yield DeniedTransaction(tx)

    @contextmanager
    def denying(path):
        with optional(path) as directory:
            yield DeniedDirectory(directory) if directory is not None and path.name == "memories" else directory

    monkeypatch.setattr(storage, "open_optional_confidential_directory", denying)
    assert hook.warn_when_memory_is_locked(home=home)
    assert "Windows memory" in capsys.readouterr().err


@pytest.mark.parametrize("shape", ["A", "B", "C"])
def test_armed_plaintext_read_warns_once(windows, shape, monkeypatch, caplog):
    _, home, _ = windows
    enroll(windows)
    mark(home)
    put(home, "MEMORY.md", b"plain entry")
    monkeypatch.setattr(hook, "_PLAINTEXT_SEEN", set())
    module = module_for(home, shape)
    path = home / "memories" / "MEMORY.md"
    with caplog.at_level("WARNING", logger=hook.__name__):
        assert module.MemoryStore._read_file(path) == ["plain entry"]
        assert module.MemoryStore._read_file(path) == ["plain entry"]
    assert caplog.text.count("is plaintext memory while memory encryption is on") == 1


@pytest.mark.parametrize("shape", ["A", "B"])
def test_keyless_unmanaged_drift_reports_backup_failed(windows, shape, monkeypatch):
    _, home, backend = windows
    put(home, "MEMORY.md", b"abcdef")
    module = module_for(home, shape)
    store = module.MemoryStore(memory_char_limit=1)
    monkeypatch.setattr(hook.time, "time", lambda: 42)
    args = ("memory", "abcdef") if shape == "A" else ("memory",)
    backup = home / "memories" / "MEMORY.md.bak.42"
    assert store._detect_external_drift(*args) == f"{backup} (BACKUP FAILED — file unchanged on disk)"
    assert not list((home / "memories").glob("*.bak.*"))
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"abcdef"
    assert not backend.calls


def test_value_error_is_classified_refusal(windows):
    home = Path("relative-home")
    module = _fake_module("C", home / "memories")
    assert hook.install_memory_hook(home=home, memory_tool_module=module, environ={})
    with pytest.raises(hook.MemoryEncryptionUnavailable) as refused:
        module.MemoryStore._read_file(home / "memories" / "MEMORY.md")
    assert isinstance(refused.value.__cause__, ValueError)


# ---------------------------------------------------------------------------
# Unsupported seams: only a checked fresh unmanaged profile may run raw upstream
# ---------------------------------------------------------------------------


def unsupported_memory_tool():
    """A seam ``classify_seam`` refuses; its raw writer publishes entries verbatim."""
    module = ModuleType("tools.memory_tool")
    module.ENTRY_DELIMITER = None

    class MemoryStore:
        @staticmethod
        def _write_file(path, entries):
            Path(path).write_text(ENTRY_DELIMITER.join(entries), encoding="utf-8")

        @staticmethod
        def _read_file(path):
            return []

    module.MemoryStore = MemoryStore
    return module


def journey_module(home, *, mismatch=False, edit=True):
    module = ModuleType("agent.learning_mutations")
    calls = module.calls = []
    module.parse_node_kind = lambda value: "memory" if value.startswith("memory:") else "skill"
    module._memories_dir = lambda: home / "memories"
    module._MEMORY_FILES = {"memory": "MEMORY.md", "profile": "USER.md"}

    def delete_node(node_id):
        calls.append(node_id)
        return {"ok": True}

    def delete_node_forced(node_id, force=False):
        calls.append(node_id)
        return {"ok": True}

    def edit_node(node_id, content):
        calls.append(node_id)
        return {"ok": True}

    module.delete_node = delete_node_forced if mismatch else delete_node
    if edit:
        module.edit_node = edit_node
    return module


def retained_seal(home):
    put(home, "MEMORY.md", seal(b"retained", key=b"k" * 32, name="MEMORY.md"))


def orphan_marker(home):
    with open_private_directory(home / "mordred", create=True):
        pass
    mark(home)


def unreadable_custody(home):
    with open_private_directory(home / "mordred", create=True):
        pass
    (home / "mordred" / "windows-custody.json").mkdir()


INDETERMINATE = {"seal": retained_seal, "marker": orphan_marker, "unreadable": unreadable_custody}


class HostContext:
    def register_hook(self, name, callback):
        return None


def prepare_register(mp, home, memory_tool, journey=None):
    """The real plugin and keyvault ``except Exception`` wrappers; other installers inert."""
    from mordred_hermes import plugin
    from mordred_hermes.desktop import install as desktop
    from mordred_hermes.keyvault import _env_write_guard, _runtime_env

    mp.setattr(plugin, "COMPONENTS", (("keyvault", "mordred_hermes.keyvault"),))
    mp.setattr(_runtime_env, "install_vault_env_decrypt", lambda **_kwargs: 0)
    mp.setattr(_env_write_guard, "install_env_write_guard", lambda **_kwargs: False)
    mp.setattr(desktop, "ensure_page", lambda: None)
    mp.setenv("HERMES_HOME", str(home))
    mp.setitem(sys.modules, "tools.memory_tool", memory_tool)
    mp.setitem(sys.modules, "agent.learning_mutations", journey or journey_module(home))
    return lambda: plugin.register(HostContext())


@contextmanager
def _optional(path):
    with ExitStack() as stack:
        try:
            directory = stack.enter_context(open_private_directory(path))
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
            directory = None
        yield directory


def emulate_windows(mp):
    """Child-process copy of the ``fs``/``memory``/``windows`` fixture patches."""
    from mordred_hermes import _config_io as cio
    from mordred_hermes.keyvault import _memory_storage as storage
    from mordred_hermes.keyvault import _windows_custody as custody
    from tests._keyvault_fakes import FakeBackend
    from tests.test_windows_custody_profile import SID

    backend = FakeBackend()
    mp.setattr(cio, "open_confidential_directory", open_private_directory)
    for owner in (cio, custody, storage):
        mp.setattr(owner, "open_optional_confidential_directory", _optional)
    mp.setattr(cio, "open_optional_private_directory", _optional)
    mp.setattr(custody, "current_principal_id", lambda: SID)
    mp.setattr(custody, "windows_backend", lambda: backend)
    mp.setattr(storage, "open_confidential_directory", open_private_directory)
    mp.setattr(storage, "windows_memory_runtime_admitted", lambda: True)
    mp.setattr(hook, "sys", Win32Sys())


CHILD = """
import sys
import threading
from pathlib import Path

import pytest

from tests.test_windows_memory_hook import emulate_windows, prepare_register, unsupported_memory_tool

home = Path(sys.argv[1])
memory_tool = unsupported_memory_tool()
with pytest.MonkeyPatch.context() as mp:
    emulate_windows(mp)
    worker = threading.Thread(target=prepare_register(mp, home, memory_tool))
    worker.start()
    worker.join()
    print("continued", flush=True)
    memory_tool.MemoryStore._write_file(home / "memories" / "MEMORY.md", ["plain"])
print((home / "memories" / "MEMORY.md").read_text(encoding="utf-8"), flush=True)
"""


@pytest.mark.parametrize("state", [*INDETERMINATE, "fresh"])
def test_worker_register_hard_exits_unless_fresh(memory, state):
    _, home, _ = memory
    if state == "fresh":
        put(home, "USER.md", b"plain user")
    else:
        INDETERMINATE[state](home)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("HERMES_", "MORDRED_"))}
    env |= {"HERMES_HOME": str(home), "PYTHONUTF8": "1"}
    child = subprocess.run(
        [sys.executable, "-c", CHILD, str(home)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if state == "fresh":
        assert child.returncode == 0, child.stderr
        assert child.stdout.split() == ["continued", "plain"]
        assert (home / "memories" / "USER.md").read_bytes() == b"plain user"
    else:
        assert child.returncode == 1, child.stderr
        assert "continued" not in child.stdout
        assert "refusing to start" in child.stderr


@pytest.mark.parametrize("state", list(INDETERMINATE))
def test_indeterminate_unsupported_seam_stops_register(windows, monkeypatch, capsys, state):
    _, home, _ = windows
    INDETERMINATE[state](home)
    register = prepare_register(monkeypatch, home, unsupported_memory_tool())
    with pytest.raises(SystemExit) as stopped:
        register()
    assert stopped.value.code == 1
    assert "refusing to start" in capsys.readouterr().err


@pytest.mark.parametrize("state", list(INDETERMINATE))
def test_indeterminate_unsupported_seam_stops_import_action(windows, monkeypatch, state):
    _, home, _ = windows
    INDETERMINATE[state](home)
    monkeypatch.setenv("HERMES_HOME", str(home))
    inner = SimpleNamespace(create_module=lambda spec: None, exec_module=lambda module: None)
    loader = hook._PostImportLoader(inner, hook._on_memory_tool_imported)
    with pytest.raises(SystemExit):
        loader.exec_module(unsupported_memory_tool())


def test_fresh_unmanaged_unsupported_seam_stays_plaintext(windows, monkeypatch):
    """Documented: nothing is owned or sealed, so upstream's raw seam runs in plaintext."""
    from mordred_hermes import plugin

    _, home, backend = windows
    put(home, "USER.md", b"plain user")
    memory_tool = unsupported_memory_tool()
    prepare_register(monkeypatch, home, memory_tool)()
    assert plugin.component_errors() == {}
    assert not hook.memory_hook_installed(memory_tool)
    path = home / "memories" / "MEMORY.md"
    memory_tool.MemoryStore._write_file(path, ["plain"])
    assert path.read_bytes() == b"plain"
    assert not backend.calls


def test_unresolvable_home_unsupported_seam_stops(windows, monkeypatch):
    def unavailable():
        raise RuntimeError("profile unavailable")

    monkeypatch.setattr(hook, "_live_home", unavailable)
    with pytest.raises(SystemExit):
        hook.install_memory_hook(memory_tool_module=unsupported_memory_tool(), environ={})


@pytest.mark.parametrize("managed", [True, False], ids=["managed", "fresh"])
def test_partial_wrap_failure_stops_unless_fresh(windows, managed):
    _, home, _ = windows
    if managed:
        enroll(windows)
    module = _fake_module("B", home / "memories")

    class ReadOnlySeam(type):
        def __setattr__(cls, name, value):
            if name == "_read_file":
                raise TypeError("read seam is read-only")
            super().__setattr__(name, value)

    module.MemoryStore = ReadOnlySeam("MemoryStore", (module.MemoryStore,), {})
    with pytest.raises(SystemExit if managed else TypeError):
        hook.install_memory_hook(home=home, memory_tool_module=module, environ={})


# ---------------------------------------------------------------------------
# Journey: an unsupported mutation seam is stubbed or stops unless fresh
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["managed", "seal", "unreadable"])
def test_unsupported_journey_stubbed_through_register(windows, monkeypatch, state):
    from mordred_hermes import keyvault

    _, home, _ = windows
    if state == "managed":
        enroll(windows)
    else:
        INDETERMINATE[state](home)
    module = journey_module(home, mismatch=True)
    monkeypatch.setitem(sys.modules, "agent.learning_mutations", module)
    monkeypatch.setenv("HERMES_HOME", str(home))
    keyvault._install_journey_guard()
    for result in (
        module.delete_node("memory:memory:0"),
        module.edit_node("memory:profile:0", "new"),
        module.delete_node("skill-name"),
    ):
        assert result["ok"] is False
    assert module.calls == []
    assert hook.install_journey_guard(module, home=home)


def test_unsupported_journey_fresh_unmanaged_left_alone(windows):
    _, home, _ = windows
    module = journey_module(home, mismatch=True)
    raw = module.delete_node
    assert hook.install_journey_guard(module, home=home) is False
    assert module.delete_node is raw
    assert module.delete_node("memory:memory:0") == {"ok": True}


@pytest.mark.parametrize("state", ["managed", "marker"])
def test_unlocatable_journey_mutation_stops(windows, monkeypatch, state):
    from mordred_hermes import keyvault

    _, home, _ = windows
    if state == "managed":
        enroll(windows)
    else:
        INDETERMINATE[state](home)
    monkeypatch.setitem(sys.modules, "agent.learning_mutations", journey_module(home, edit=False))
    monkeypatch.setenv("HERMES_HOME", str(home))
    with pytest.raises(SystemExit):
        keyvault._install_journey_guard()


def test_windows_journey_keys_on_computed_memory_path(windows):
    _, home, _ = windows
    module = journey_module(home)
    module.parse_node_kind = lambda value: "memory" if value.split(":")[1:2] == ["memory"] else "skill"
    assert hook.install_journey_guard(module, home=home)
    assert module.delete_node("learned:memory:0")["ok"] is False
    assert module.calls == []
