"""Canary: the memory hook against the real release or selected upstream source.

The unit tests run against faithful copies of the three upstream seam shapes;
this file runs against installed Hermes or a strictly selected main checkout. It is the tripwire
for an upstream refactor — if ``MemoryStore`` grows a new read chokepoint or
renames a parameter, ``seam_check`` stops recognising it and this fails in CI
rather than in an operator's memory directory.

Hermetic: the seam attributes are restored on the live class in a ``finally``, and
every path is under ``tmp_path`` via ``HERMES_HOME``.
"""

from __future__ import annotations

import base64
import contextlib
import os
import secrets
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _memory_hook
from mordred_hermes.keyvault._memory_hook import (
    MemoryEncryptionUnavailable,
    install_journey_guard,
    install_memory_hook,
    memory_marker_path,
    memory_seam_shape,
    seam_check,
)
from mordred_hermes.keyvault._runtime_probe import runtime_memory_encryption_available
from mordred_hermes.keyvault.memory_crypto import MAGIC, seal, unseal
from tests._upstream_canary import CanaryUnavailable, SeamDrift, import_target, verify_selected_source

_SEAM_NAMES = ("_write_file", "_read_file", "_read_raw_checked", "_detect_external_drift")
_ABSENT = object()


def _unwrap_seams(store_cls: Any) -> None:
    """Strip any hook wrappers already on the live class.

    Installation is idempotent, so a wrapper left behind by an earlier test (any
    ``register()`` call installs one bound to *that* test's home) would make this
    file's ``install_memory_hook`` a no-op and silently test nothing.
    """
    for name in _SEAM_NAMES:
        current = store_cls.__dict__.get(name)
        if current is None:
            continue
        is_static = isinstance(current, staticmethod)
        func = current.__func__ if is_static else current
        while getattr(func, "_mordred_memory_hook_wrapped", False):
            func = func.__wrapped__
        setattr(store_cls, name, staticmethod(func) if is_static else func)


@pytest.fixture
def upstream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """The live ``tools.memory_tool``, rooted at ``tmp_path`` and restored afterwards."""
    memory_tool = import_target("tools.memory_tool")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    verify_selected_source()
    store_cls = memory_tool.MemoryStore
    saved = {name: store_cls.__dict__.get(name, _ABSENT) for name in _SEAM_NAMES}
    _unwrap_seams(store_cls)
    _memory_hook._PLAINTEXT_SEEN.clear()
    try:
        yield memory_tool
    finally:
        for name, value in saved.items():
            if value is _ABSENT:
                with contextlib.suppress(AttributeError):
                    delattr(store_cls, name)
            else:
                setattr(store_cls, name, value)
        _memory_hook._PLAINTEXT_SEEN.clear()


def _arm(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = memory_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("", encoding="utf-8")
    monkeypatch.setenv("HERMES_MEMORY_KEY", base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))


def test_installed_seam_is_one_we_recognise(upstream: Any, tmp_path: Path) -> None:
    assert upstream.get_memory_dir() == tmp_path / "memories"
    ok, reason = seam_check()
    assert ok, reason
    assert memory_seam_shape() in {"A", "B", "C"}


def test_memory_round_trips_through_upstream_code(
    upstream: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _arm(tmp_path, monkeypatch)
    assert install_memory_hook(home=tmp_path) is True

    store = upstream.MemoryStore()
    store.load_from_disk()
    assert store.add("memory", "the cat is on the mat")["success"] is True

    path = tmp_path / "memories" / "MEMORY.md"
    data = path.read_bytes()
    assert data.startswith(MAGIC)
    assert b"cat is on the mat" not in data

    reloaded = upstream.MemoryStore()
    reloaded.load_from_disk()
    assert reloaded.memory_entries == ["the cat is on the mat"]

    # replace / remove go through _reload_target -> the wrapped read seam and,
    # on shapes A/B, the wrapped drift check.
    assert store.replace("memory", "cat is on", "the dog is on the mat")["success"] is True
    after_replace = upstream.MemoryStore()
    after_replace.load_from_disk()
    assert after_replace.memory_entries == ["the dog is on the mat"]
    assert path.read_bytes().startswith(MAGIC)

    assert store.remove("memory", "dog is on")["success"] is True
    after_remove = upstream.MemoryStore()
    after_remove.load_from_disk()
    assert after_remove.memory_entries == []


def test_sealed_memory_without_a_key_refuses_instead_of_wiping(
    upstream: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _arm(tmp_path, monkeypatch)
    install_memory_hook(home=tmp_path)
    store = upstream.MemoryStore()
    store.load_from_disk()
    store.add("memory", "the cat is on the mat")

    path = tmp_path / "memories" / "MEMORY.md"
    before = path.read_bytes()
    monkeypatch.delenv("HERMES_MEMORY_KEY")

    # Upstream propagates the refusal out of `add` (it wraps neither the reload
    # nor save_to_disk in an except) — the sealed bytes stay intact either way.
    with pytest.raises(MemoryEncryptionUnavailable):
        store.add("memory", "another fact")
    assert path.read_bytes() == before


def test_write_refusal_propagates_out_of_store_add(
    upstream: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Armed with no key over a *plaintext* file: the read passes through, so it is
    the WRITE that refuses — pinning that upstream does not swallow it into an
    error dict."""
    _arm(tmp_path, monkeypatch)
    monkeypatch.delenv("HERMES_MEMORY_KEY")
    install_memory_hook(home=tmp_path)

    mem_dir = tmp_path / "memories"
    mem_dir.mkdir(parents=True, exist_ok=True)
    path = mem_dir / "MEMORY.md"
    path.write_text("legacy plaintext entry", encoding="utf-8")
    before = path.read_bytes()

    store = upstream.MemoryStore()
    store.load_from_disk()
    assert store.memory_entries == ["legacy plaintext entry"]

    with pytest.raises(MemoryEncryptionUnavailable):
        store.add("memory", "another fact")
    assert path.read_bytes() == before


def test_journey_guard_wraps_the_real_learning_mutations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The journey-guard half of the canary: ``delete_node`` / ``edit_node`` still
    take the parameters we pin. A rename upstream silently turns the guard into a
    no-op, and ``learning_graph`` then deletes real entries by raw-file index."""
    mutations = import_target("agent.learning_mutations", optional=True)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    saved = {name: getattr(mutations, name) for name in ("delete_node", "edit_node")}
    try:
        assert install_journey_guard(mutations, home=tmp_path) is True
        assert getattr(mutations.delete_node, _memory_hook._WRAPPED_FLAG, False) is True
        assert getattr(mutations.edit_node, _memory_hook._WRAPPED_FLAG, False) is True
        path = tmp_path / "memories" / "MEMORY.md"
        path.parent.mkdir(parents=True)
        path.write_text("first entry", encoding="utf-8")
        assert mutations.edit_node("memory:memory:0", "edited entry")["ok"] is True
        assert path.read_text().strip() == "edited entry"
        assert mutations.delete_node("memory:memory:0")["ok"] is True
        assert path.read_text().strip() == ""
        _arm(tmp_path, monkeypatch)
        key = base64.urlsafe_b64decode(os.environ["HERMES_MEMORY_KEY"])
        sealed = seal(b"protected entry", key=key, name=path.name)
        path.write_bytes(sealed)
        for result in (mutations.edit_node("memory:memory:0", "lost entry"), mutations.delete_node("memory:memory:0")):
            assert result["ok"] is False
            assert "sealed" in result["message"]
            assert path.read_bytes() == sealed
    finally:
        for name, value in saved.items():
            setattr(mutations, name, value)


def test_runtime_probe_sees_this_interpreter_as_capable(tmp_path: Path) -> None:
    import_target("tools.memory_tool")
    ok, detail = runtime_memory_encryption_available(home=tmp_path, runtime_python=Path(sys.executable))
    assert ok is True, detail
    assert "seam" in detail


def test_probe_entry_point_rejects_other_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    import_target("tools.memory_tool")
    capsys.readouterr()
    assert _memory_hook._main(["--probe"]) == 0
    assert capsys.readouterr().out.strip() in {"A", "B", "C"}
    assert _memory_hook._main([]) == 2
    assert "--probe" in capsys.readouterr().err


def test_probe_entry_point_exits_zero(tmp_path: Path) -> None:
    import_target("tools.memory_tool")
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-m", "mordred_hermes.keyvault._memory_hook", "--probe"],
        capture_output=True,
        text=True,
        check=False,
        env={
            **{k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "HERMES_MEMORY_KEY")},
            "HERMES_HOME": str(tmp_path),
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() in {"A", "B", "C"}


@pytest.fixture(autouse=True)
def _macos_key_custody_contract(monkeypatch):
    """These regressions exercise macOS env/vault custody on every CI OS."""
    import mordred_hermes.keyvault._memory_hook as module
    from tests._helpers import PlatformSys

    monkeypatch.setattr(module, "sys", PlatformSys("darwin"))


def test_sanitized_child_uses_selected_source(tmp_path: Path) -> None:
    import subprocess

    from tests._upstream_canary import expected_root

    if expected_root() is None:
        return
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "HERMES_MEMORY_KEY")}
    env["HERMES_HOME"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-c", "from tests._upstream_canary import child_main; raise SystemExit(child_main())"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 11:
        raise SeamDrift(proc.stdout + proc.stderr)
    if proc.returncode != 0:
        raise CanaryUnavailable(proc.stdout + proc.stderr)
    print("CANARY_CHILD_PROVENANCE\n" + proc.stdout, end="")
    assert "CANARY_SOURCE tools.memory_tool:" in proc.stdout
    assert "CANARY_SOURCE MemoryStore:" in proc.stdout


def test_drift_backup_is_sealed_and_preserves_external_content(
    upstream: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _arm(tmp_path, monkeypatch)
    assert install_memory_hook(home=tmp_path)
    store = upstream.MemoryStore()
    store.load_from_disk()
    path = tmp_path / "memories" / "MEMORY.md"
    raw = "external writer " + "x" * (store.memory_char_limit + 100)
    key = base64.urlsafe_b64decode(os.environ["HERMES_MEMORY_KEY"])
    before = seal(raw.encode(), key=key, name=path.name)
    path.write_bytes(before)
    result = store.remove("memory", "external writer")
    backups = list(path.parent.glob("MEMORY.md.bak.*"))
    if memory_seam_shape() == "C":
        # The declared floor has no drift-backup seam; mutations still ran.
        assert backups == []
        return
    assert result["success"] is False
    assert path.read_bytes() == before
    assert len(backups) == 1
    backup = backups[0]
    assert backup.read_bytes().startswith(MAGIC)
    assert unseal(backup.read_bytes(), key=key, name=backup.name).decode() == raw
    path.write_text("repaired entry", encoding="utf-8")
    assert store.add("memory", "another fact")["success"]
    assert path.read_bytes().startswith(MAGIC)
    if memory_seam_shape() == "A":
        # Current main's snapshot seam also seals backups from an out-of-process
        # plaintext writer. Shape B delegates that pre-existing exposure path.
        monkeypatch.setattr(_memory_hook.time, "time", lambda: 1_700_000_000)
        path.write_text(raw, encoding="utf-8")
        result = store.remove("memory", "external writer")
        assert result["success"] is False
        assert path.read_text() == raw
        plaintext_backup = path.with_suffix(path.suffix + ".bak.1700000000")
        assert plaintext_backup.read_bytes().startswith(MAGIC)
        assert unseal(plaintext_backup.read_bytes(), key=key, name=plaintext_backup.name).decode() == raw
        assert backup.read_bytes().startswith(MAGIC)


@pytest.fixture(autouse=True)
def _selected_source_contract():
    verify_selected_source()
    yield
    verify_selected_source()
