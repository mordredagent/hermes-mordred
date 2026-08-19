"""Unit tests for the agent-memory encryption hook (:mod:`keyvault._memory_hook`).

Upstream ``tools/memory_tool.py`` exposes three different seam shapes across the
Hermes releases we support, and wrapping the *wrong* one silently destroys memory
(a sealed file read as "empty" is overwritten by the next write). So the fakes
below re-implement each shape's ``_read_file`` / ``_read_raw_checked`` /
``_write_file`` / ``_detect_external_drift`` with the upstream bodies:

* **A** — hermes-agent main / 0.20+ (checked raw read, drift takes ``raw``)
* **B** — 0.16-0.19 (``_read_file`` reads raw itself, drift re-reads the file)
* **C** — 0.13-0.15 (no drift detection at all)

Each fake is a fresh subclass per test, so a wrapper installed on one test's
class cannot leak into another. The shape-A / shape-B readers route through
``cls.`` rather than a hard-bound class name for the same reason upstream routes
through ``MemoryStore.``: the wrapper must be picked up at call time.
"""

from __future__ import annotations

import base64
import os
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mordred_hermes.keyvault import _memory_hook
from mordred_hermes.keyvault._memory_hook import (
    MemoryEncryptionUnavailable,
    classify_seam,
    install_memory_hook,
    memory_hook_installed,
    memory_marker_path,
    memory_optout_marker_path,
    memory_seam_shape,
)
from mordred_hermes.keyvault.memory_crypto import MAGIC, is_sealed, seal, unseal

ENTRY_DELIMITER = "\n§\n"
KEY = bytes(range(32))
KEY_ENV = base64.urlsafe_b64encode(KEY).decode("ascii")
OTHER_KEY_ENV = base64.urlsafe_b64encode(bytes(range(32, 64))).decode("ascii")

SHAPES = ["A", "B", "C"]


# --------------------------------------------------------------------------
# Fake upstream modules
# --------------------------------------------------------------------------


class _FakeStoreCommon:
    """State + the two seams every shape shares."""

    mem_dir: Path  # set on the per-test subclass

    def __init__(self, memory_char_limit: int = 2200, user_char_limit: int = 1375) -> None:
        self.memory_entries: list[str] = []
        self.user_entries: list[str] = []
        self.memory_char_limit = memory_char_limit
        self.user_char_limit = user_char_limit

    @classmethod
    def _path_for(cls, target: str) -> Path:
        return cls.mem_dir / ("USER.md" if target == "user" else "MEMORY.md")

    def _char_limit(self, target: str) -> int:
        return self.user_char_limit if target == "user" else self.memory_char_limit

    def _entries_for(self, target: str) -> list[str]:
        return self.user_entries if target == "user" else self.memory_entries

    def _set_entries(self, target: str, entries: list[str]) -> None:
        if target == "user":
            self.user_entries = entries
        else:
            self.memory_entries = entries

    def save_to_disk(self, target: str) -> None:
        self._write_file(self._path_for(target), self._entries_for(target))

    @staticmethod
    def _write_file(path: Path, entries: list[str]) -> None:
        content = ENTRY_DELIMITER.join(entries) if entries else ""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(content, encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            raise RuntimeError(f"Failed to write memory file {path}: {exc}") from exc


class _FakeStoreC(_FakeStoreCommon):
    """Shape C (0.13-0.15): ``_read_file`` reads raw itself; no drift detection."""

    @classmethod
    def _read_file(cls, path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return []
        if not raw.strip():
            return []
        entries = [e.strip() for e in raw.split(ENTRY_DELIMITER)]
        return [e for e in entries if e]

    def _reload_target(self, target: str) -> None:
        fresh = list(dict.fromkeys(self._read_file(self._path_for(target))))
        self._set_entries(target, fresh)


class _FakeStoreB(_FakeStoreC):
    """Shape B (0.16-0.19): C plus a drift check that re-reads the file itself."""

    def _detect_external_drift(self, target: str) -> str | None:
        path = self._path_for(target)
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        if not raw.strip():
            return None
        parsed = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
        roundtrip = ENTRY_DELIMITER.join(parsed)
        max_entry_len = max((len(e) for e in parsed), default=0)
        if raw.strip() == roundtrip and max_entry_len <= self._char_limit(target):
            return None
        bak_path = path.with_suffix(path.suffix + f".bak.{int(time.time())}")
        try:
            bak_path.write_text(raw, encoding="utf-8")
        except OSError:
            return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
        return str(bak_path)

    def _reload_target(self, target: str, *, skip_drift: bool = False) -> str | None:  # type: ignore[override]
        bak = None if skip_drift else self._detect_external_drift(target)
        fresh = list(dict.fromkeys(self._read_file(self._path_for(target))))
        self._set_entries(target, fresh)
        return bak


class _FakeStoreA(_FakeStoreCommon):
    """Shape A (main / 0.20+): checked raw read; drift operates on that snapshot."""

    @staticmethod
    def _read_raw_checked(path: Path) -> tuple[str, bool]:
        if not path.exists():
            return "", True
        try:
            return path.read_text(encoding="utf-8-sig"), True
        except (OSError, UnicodeDecodeError):
            return "", False

    @staticmethod
    def _parse_entries(raw: str) -> list[str]:
        if not raw.strip():
            return []
        return [e for e in (part.strip() for part in raw.split(ENTRY_DELIMITER)) if e]

    @classmethod
    def _read_entries_checked(cls, path: Path) -> tuple[list[str], bool]:
        raw, read_ok = cls._read_raw_checked(path)
        if not read_ok:
            return [], False
        return cls._parse_entries(raw), True

    @classmethod
    def _read_file(cls, path: Path) -> list[str]:
        return cls._read_entries_checked(path)[0]

    def _detect_external_drift(self, target: str, raw: str) -> str | None:
        path = self._path_for(target)
        if not raw.strip():
            return None
        parsed = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
        roundtrip = ENTRY_DELIMITER.join(parsed)
        max_entry_len = max((len(e) for e in parsed), default=0)
        if raw.strip() == roundtrip and max_entry_len <= self._char_limit(target):
            return None
        bak_path = path.with_suffix(path.suffix + f".bak.{int(time.time())}")
        try:
            bak_path.write_text(raw, encoding="utf-8")
        except OSError:
            return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
        return str(bak_path)

    def _reload_target(self, target: str, *, skip_drift: bool = False) -> str | None:
        path = self._path_for(target)
        raw, read_ok = self._read_raw_checked(path)
        if not read_ok:
            return "READ FAILED"
        bak = None if skip_drift else self._detect_external_drift(target, raw)
        self._set_entries(target, list(dict.fromkeys(self._parse_entries(raw))))
        return bak


_BASES: dict[str, type[_FakeStoreCommon]] = {"A": _FakeStoreA, "B": _FakeStoreB, "C": _FakeStoreC}


def _fake_module(shape: str, mem_dir: Path) -> ModuleType:
    """A fresh fake ``tools.memory_tool`` of ``shape`` writing under ``mem_dir``."""
    module = ModuleType(f"fake_memory_tool_{shape.lower()}")
    module.ENTRY_DELIMITER = ENTRY_DELIMITER  # type: ignore[attr-defined]
    module.MemoryStore = type("MemoryStore", (_BASES[shape],), {"mem_dir": mem_dir})  # type: ignore[attr-defined]
    return module


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_plaintext_notes() -> Iterator[None]:
    """The plaintext-seen set is module-global (one warning per path per process)."""
    _memory_hook._PLAINTEXT_SEEN.clear()
    yield
    _memory_hook._PLAINTEXT_SEEN.clear()


@pytest.fixture
def mem_dir(tmp_path: Path) -> Path:
    path = tmp_path / "memories"
    path.mkdir()
    return path


@pytest.fixture(params=SHAPES)
def shape(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def _arm(home: Path) -> None:
    marker = memory_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("", encoding="utf-8")


def _install(
    module: ModuleType,
    home: Path,
    *,
    key: str | None = KEY_ENV,
    armed: bool = True,
    environ: dict[str, str] | None = None,
) -> tuple[bool, dict[str, str]]:
    if armed:
        _arm(home)
    env = {} if environ is None else environ
    if key is not None:
        env["HERMES_MEMORY_KEY"] = key
    ok = install_memory_hook(home=home, memory_tool_module=module, environ=env)
    return ok, env


def _memory_path(module: ModuleType) -> Path:
    return Path(module.MemoryStore._path_for("memory"))


# --------------------------------------------------------------------------
# Seam classification
# --------------------------------------------------------------------------


def test_classify_seam_recognises_each_shape(shape: str, mem_dir: Path) -> None:
    assert classify_seam(_fake_module(shape, mem_dir)) == (shape, "")


def test_classify_seam_rejects_missing_write_file(mem_dir: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.MemoryStore._write_file = None  # present but not callable
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "_write_file" in reason


def test_classify_seam_rejects_wrong_parameter_names(mem_dir: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.MemoryStore._write_file = staticmethod(lambda p, lines: None)
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "_write_file" in reason


def test_classify_seam_rejects_non_str_delimiter(mem_dir: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = b"\n\xc2\xa7\n"
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "ENTRY_DELIMITER" in reason


def test_classify_seam_rejects_mixed_shape(mem_dir: Path) -> None:
    # `_read_raw_checked` says shape A, but the drift signature is shape B's.
    module = _fake_module("B", mem_dir)
    module.MemoryStore._read_raw_checked = staticmethod(lambda path: ("", True))
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "_detect_external_drift" in reason


def test_classify_seam_rejects_missing_memory_store() -> None:
    module = ModuleType("fake_memory_tool_empty")
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "MemoryStore" in reason


def test_memory_seam_shape_reports_the_shape(shape: str, mem_dir: Path) -> None:
    assert memory_seam_shape(_fake_module(shape, mem_dir)) == shape


# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------


def test_install_is_idempotent(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    assert _install(module, tmp_path)[0] is True
    first_write = module.MemoryStore._write_file
    assert install_memory_hook(home=tmp_path, memory_tool_module=module, environ={}) is True
    assert module.MemoryStore._write_file is first_write
    assert memory_hook_installed(module) is True


def test_install_stamps_static_seams_as_staticmethods(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    # Reassigned as a plain function, `self._write_file(path, entries)` would bind
    # `self` to `path` — the whole seam would silently take the wrong arguments.
    assert isinstance(module.MemoryStore.__dict__["_write_file"], staticmethod)


def test_install_is_a_noop_in_safe_mode(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    original = module.MemoryStore._write_file
    _arm(tmp_path)
    ok = install_memory_hook(
        home=tmp_path,
        memory_tool_module=module,
        environ={"HERMES_MEMORY_KEY": KEY_ENV, "HERMES_SAFE_MODE": "1"},
    )
    assert ok is False
    assert module.MemoryStore._write_file is original
    assert memory_hook_installed(module) is False


def test_install_fails_open_on_unsupported_seam_when_not_armed(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = None
    assert install_memory_hook(home=tmp_path, memory_tool_module=module, environ={}) is False
    assert memory_hook_installed(module) is False


def test_install_refuses_to_start_on_unsupported_seam_when_armed(
    mem_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = None
    _arm(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        install_memory_hook(home=tmp_path, memory_tool_module=module, environ={"HERMES_MEMORY_KEY": KEY_ENV})
    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert "refusing to start" in stderr
    assert "HERMES_SAFE_MODE" in stderr


def test_optout_marker_disarms_the_hook(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    optout = memory_optout_marker_path(tmp_path)
    optout.parent.mkdir(parents=True, exist_ok=True)
    optout.write_text("", encoding="utf-8")

    path = _memory_path(module)
    module.MemoryStore._write_file(path, ["plain entry"])
    assert path.read_text(encoding="utf-8") == "plain entry"


# --------------------------------------------------------------------------
# Write seam
# --------------------------------------------------------------------------


def test_not_armed_write_and_read_are_byte_identical(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    wrapped = _fake_module(shape, mem_dir)
    control = _fake_module(shape, mem_dir / "control")
    _install(wrapped, tmp_path, armed=False)

    entries = ["first entry", "second entry"]
    wrapped_path = _memory_path(wrapped)
    control_path = _memory_path(control)
    wrapped.MemoryStore._write_file(wrapped_path, entries)
    control.MemoryStore._write_file(control_path, entries)

    assert wrapped_path.read_bytes() == control_path.read_bytes()
    assert wrapped.MemoryStore._read_file(wrapped_path) == control.MemoryStore._read_file(control_path) == entries


def test_armed_write_seals_the_file(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)

    module.MemoryStore._write_file(path, ["the cat is on the mat", "second entry"])

    data = path.read_bytes()
    assert data.startswith(MAGIC + b"\n")
    assert b"cat is on the mat" not in data
    assert unseal(data, key=KEY, name="MEMORY.md").decode("utf-8") == "the cat is on the mat\n§\nsecond entry"


def test_sealed_blob_survives_the_single_entry_join(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    # The wrapper hands the sealed text back to upstream as a ONE-entry list, so
    # upstream's `delimiter.join(entries)` must be the identity for it.
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    module.MemoryStore._write_file(path, ["only entry"])
    sealed = path.read_text(encoding="utf-8")
    assert ENTRY_DELIMITER.join([sealed]) == sealed
    assert ENTRY_DELIMITER not in sealed


def test_armed_write_without_a_key_raises_and_leaves_the_file(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=None)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    before = path.read_bytes()

    with pytest.raises(MemoryEncryptionUnavailable):
        module.MemoryStore._write_file(path, ["new entry"])

    assert path.read_bytes() == before


def test_armed_write_with_an_unusable_key_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    # A malformed key is "no key" — never a silent plaintext write.
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key="base64:not-a-32-byte-key")
    with pytest.raises(MemoryEncryptionUnavailable):
        module.MemoryStore._write_file(_memory_path(module), ["new entry"])


def test_memory_encryption_unavailable_is_a_runtime_error() -> None:
    # Upstream catches RuntimeError around memory writes, so the refusal is
    # reported to the model instead of crashing the process.
    assert issubclass(MemoryEncryptionUnavailable, RuntimeError)


# --------------------------------------------------------------------------
# Read seam
# --------------------------------------------------------------------------


def test_armed_read_returns_the_plaintext_entries(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    path.write_bytes(seal("first entry\n§\nsecond entry".encode(), key=KEY, name="MEMORY.md"))

    assert module.MemoryStore._read_file(path) == ["first entry", "second entry"]


def test_armed_read_of_a_plaintext_file_passes_through_and_is_noted(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    path.write_text("legacy entry", encoding="utf-8")

    assert module.MemoryStore._read_file(path) == ["legacy entry"]
    assert str(path) in _memory_hook._PLAINTEXT_SEEN


def test_read_of_an_absent_file_is_unchanged(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    assert module.MemoryStore._read_file(mem_dir / "MEMORY.md") == []
    assert not _memory_hook._PLAINTEXT_SEEN


def test_read_of_a_sealed_file_without_a_key_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=None)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))

    with pytest.raises(MemoryEncryptionUnavailable, match="HERMES_MEMORY_KEY"):
        module.MemoryStore._read_file(path)


def test_read_of_a_plaintext_file_without_a_key_still_works(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=None)
    path = _memory_path(module)
    path.write_text("legacy entry", encoding="utf-8")
    assert module.MemoryStore._read_file(path) == ["legacy entry"]


def test_read_of_a_wrong_key_file_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=OTHER_KEY_ENV)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))

    with pytest.raises(MemoryEncryptionUnavailable, match="authenticate"):
        module.MemoryStore._read_file(path)


def test_read_of_a_tampered_file_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    sealed = bytearray(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    sealed[-4] = ord("A") if sealed[-4] != ord("A") else ord("B")
    path.write_bytes(bytes(sealed))

    with pytest.raises(MemoryEncryptionUnavailable):
        module.MemoryStore._read_file(path)


def test_read_of_a_sealed_file_while_disarmed_still_decrypts(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    # Turning the marker off must not make already-sealed memories unreadable.
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    assert module.MemoryStore._read_file(path) == ["prior entry"]


def test_shape_a_read_preserves_the_read_ok_contract(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)

    assert module.MemoryStore._read_raw_checked(path) == ("", True)  # absent → clean empty

    path.write_bytes(b"\xff\xfe not utf-8")
    assert module.MemoryStore._read_raw_checked(path) == ("", False)  # unreadable → abort

    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    assert module.MemoryStore._read_raw_checked(path) == ("prior entry", True)


# --------------------------------------------------------------------------
# Drift detection
# --------------------------------------------------------------------------


def test_shape_a_drift_seals_the_plaintext_backup(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore()
    path = _memory_path(module)
    raw = "x" * (store.memory_char_limit + 10)  # oversize entry = drift
    path.write_text(raw, encoding="utf-8")

    result = store._detect_external_drift("memory", raw)

    bak = Path(str(result))
    assert bak.is_file()
    assert is_sealed(bak.read_bytes())
    assert unseal(bak.read_bytes(), key=KEY, name=bak.name).decode("utf-8") == raw


def test_shape_a_drift_passes_a_clean_result_through(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore()

    assert store._detect_external_drift("memory", "clean entry") is None
    assert list(mem_dir.glob("*.bak.*")) == []


def test_shape_a_drift_tolerates_a_failed_backup(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    failed = f"{mem_dir / 'MEMORY.md.bak.1'} (BACKUP FAILED — file unchanged on disk)"
    module.MemoryStore._detect_external_drift = lambda self, target, raw: failed
    _install(module, tmp_path)
    store = module.MemoryStore()

    assert store._detect_external_drift("memory", "x" * 9000) == failed
    assert not (mem_dir / "MEMORY.md.bak.1").exists()


def test_shape_b_drift_does_not_false_positive_on_a_sealed_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore(memory_char_limit=80)
    path = _memory_path(module)
    plaintext = "first entry\n§\nsecond entry"
    path.write_bytes(seal(plaintext.encode(), key=KEY, name="MEMORY.md"))
    # The sealed text is far longer than the char limit; the check must run on
    # the plaintext or every replace/remove would be refused.
    assert len(path.read_text(encoding="utf-8")) > store.memory_char_limit

    assert store._detect_external_drift("memory") is None


def test_shape_b_drift_backs_up_a_sealed_file_with_an_oversize_entry(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore(memory_char_limit=40)
    path = _memory_path(module)
    plaintext = "x" * 100
    path.write_bytes(seal(plaintext.encode(), key=KEY, name="MEMORY.md"))

    result = store._detect_external_drift("memory")

    bak = Path(str(result))
    assert bak.is_file()
    assert bak.name.startswith("MEMORY.md.bak.")
    assert unseal(bak.read_bytes(), key=KEY, name=bak.name).decode("utf-8") == plaintext


def test_shape_b_drift_delegates_for_a_plaintext_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    calls: list[str] = []
    original = module.MemoryStore._detect_external_drift

    def _spy(self: Any, target: str) -> str | None:
        calls.append(target)
        return original(self, target)

    module.MemoryStore._detect_external_drift = _spy
    _install(module, tmp_path)
    store = module.MemoryStore(memory_char_limit=40)
    path = _memory_path(module)
    path.write_text("x" * 100, encoding="utf-8")

    result = store._detect_external_drift("memory")

    assert calls == ["memory"]
    assert Path(str(result)).is_file()
    assert not is_sealed(Path(str(result)).read_bytes())


def test_shape_b_drift_delegates_for_an_absent_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore()
    assert store._detect_external_drift("memory") is None


def test_shape_b_drift_raises_for_an_undecryptable_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path, key=OTHER_KEY_ENV)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    store = module.MemoryStore()

    with pytest.raises(MemoryEncryptionUnavailable):
        store._detect_external_drift("memory")


def test_shape_c_has_no_drift_wrapper(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("C", mem_dir)
    _install(module, tmp_path)
    assert not hasattr(module.MemoryStore, "_detect_external_drift")


# --------------------------------------------------------------------------
# End-to-end mutate cycle (the data-loss regression)
# --------------------------------------------------------------------------


def test_mutate_cycle_keeps_prior_entries(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)

    first = module.MemoryStore()
    first._set_entries("memory", ["first entry"])
    first.save_to_disk("memory")

    second = module.MemoryStore()
    assert second._reload_target("memory") is None
    assert second._entries_for("memory") == ["first entry"]

    second._set_entries("memory", [*second._entries_for("memory"), "second entry"])
    second.save_to_disk("memory")

    third = module.MemoryStore()
    third._reload_target("memory")
    assert third._entries_for("memory") == ["first entry", "second entry"]
    assert is_sealed(path.read_bytes())
