"""Each supported Windows memory seam must avoid upstream raw I/O."""

from types import SimpleNamespace

import pytest

from mordred_hermes._private_fs import PrivateFSError
from mordred_hermes.keyvault import _memory_hook as hook
from mordred_hermes.keyvault.memory_crypto import is_sealed, seal, unseal
from tests.test_keyvault_memory_hook import ENTRY_DELIMITER, _fake_module
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_storage import enroll, mark, put
from tests.test_windows_memory_storage import memory as memory


@pytest.fixture
def windows(memory, monkeypatch):
    monkeypatch.setattr(hook, "sys", SimpleNamespace(**(vars(hook.sys) | {"platform": "win32"})))
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
    assert unseal(path.read_bytes(), key=key, name=path.name) == b"gamma"


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
    assert unseal(path.read_bytes(), key=key, name=path.name) == b"abcdef"
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


def test_checked_session_diagnosis_reports_denial(windows, capsys):
    _, home, _ = windows
    put(home, "MEMORY.md", b"bad\xff")
    hook.sys.stderr = __import__("sys").stderr
    assert hook.warn_when_memory_is_locked(home=home)
    assert "Windows memory" in capsys.readouterr().err
