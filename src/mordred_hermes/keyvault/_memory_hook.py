"""Mordred-owned at-rest encryption for Hermes agent memory.

No hermes-agent release encrypts ``~/.hermes/memories/*.md``, so this module
wraps upstream's private ``tools/memory_tool.py`` seam and seals the bytes on the
way out / opens them on the way in (format: :mod:`.memory_crypto`). Same
defensive posture as :mod:`._env_write_guard`: upstream ships no API stability
guarantee, so the seam is *classified by signature* before anything is wrapped
and an unrecognised shape is refused rather than guessed at.

Three shapes exist in the wild; wrapping the wrong one is a data-loss bug, not a
cosmetic one — a sealed file that a read seam reports as "empty" is overwritten
by the next write:

============  ==================================  ================================
Shape         Read chokepoint                     Drift detection
============  ==================================  ================================
A (0.20+)     ``_read_raw_checked(path)``         ``_detect_external_drift(self, target, raw)``
B (0.16-19)   ``_read_file(path)``                ``_detect_external_drift(self, target)``
C (0.13-15)   ``_read_file(path)``                none
============  ==================================  ================================

Arming is evaluated **per call**, never cached: the operator can pause the
feature (opt-out marker) mid-session, and the key arrives in ``os.environ`` from
the vault shim, which may run after this module is imported.

**Fail-closed on the write side, loud on the read side.** While armed we never
write plaintext, and a sealed file that cannot be decrypted raises
:class:`MemoryEncryptionUnavailable` instead of degrading to "no entries" — in
shapes B/C that degradation would let the next ``add`` overwrite the sealed file
(upstream's own wipe class, issue #26045), and in shape A the operator would
silently see an empty memory.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from .._home import hermes_home as _hermes_home
from .._runtime_bootstrap import _SAFE_MODE_TRUTHY
from .memory_crypto import MemoryCryptoError, decode_key, is_sealed, seal, unseal

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = [
    "MemoryEncryptionUnavailable",
    "classify_seam",
    "install_memory_hook",
    "memory_hook_installed",
    "memory_marker_path",
    "memory_optout_marker_path",
    "memory_seam_shape",
    "seam_check",
]

logger = logging.getLogger(__name__)

#: Opt-IN marker: its presence arms the hook (mirrors ``_config_bootstrap._MARKER_SUBPATH``).
_MEMORY_MARKER_SUBPATH: Final = ("mordred", "memory-vault.marker")
#: Opt-OUT marker: the operator paused the feature (mirrors ``_runtime_env._ENV_OPTOUT_SUBPATH``).
_MEMORY_OPTOUT_SUBPATH: Final = ("mordred", "memory-vault.optout")

_MEMORY_KEY_ENV: Final = "HERMES_MEMORY_KEY"

#: Stamped on every wrapper so a second install is a no-op (idempotent).
_WRAPPED_FLAG: Final = "_mordred_memory_hook_wrapped"

_REMEDY: Final = (
    "run `hermes-mordred encryption enable env` so HERMES_MEMORY_KEY is injected, "
    "or `hermes-mordred encryption disable memory`"
)

#: Paths already reported as plaintext — one warning per path per process.
_PLAINTEXT_SEEN: set[str] = set()


class MemoryEncryptionUnavailable(RuntimeError):
    """Memory could not be sealed or opened.

    A ``RuntimeError`` on purpose: that is what upstream's memory write path
    already raises for an I/O failure, so callers that catch it report the
    refusal to the model instead of crashing the process.
    """


def memory_marker_path(home: Path) -> Path:
    """The opt-in marker path: ``<home>/mordred/memory-vault.marker``."""
    return home.joinpath(*_MEMORY_MARKER_SUBPATH)


def memory_optout_marker_path(home: Path) -> Path:
    """The opt-out marker path: ``<home>/mordred/memory-vault.optout``."""
    return home.joinpath(*_MEMORY_OPTOUT_SUBPATH)


@dataclass(frozen=True)
class _HookConfig:
    """What the wrappers close over. ``home`` / ``environ`` are injectable for tests."""

    home: Path
    environ: Mapping[str, str]
    delimiter: str

    @property
    def armed(self) -> bool:
        """Whether sealing is on **right now** — re-read on every call, never cached."""
        if _safe_mode(self.environ):
            return False
        return memory_marker_path(self.home).exists() and not memory_optout_marker_path(self.home).exists()

    @property
    def key(self) -> bytes | None:
        """The live memory key, or ``None`` when unset / unusable."""
        value = self.environ.get(_MEMORY_KEY_ENV)
        if not value:
            return None
        try:
            return decode_key(value)
        except MemoryCryptoError:
            return None


def _safe_mode(environ: Mapping[str, str]) -> bool:
    """Hermes's explicit plugin-recovery escape hatch (same truthy set as the bootstrap)."""
    return environ.get("HERMES_SAFE_MODE", "").strip().casefold() in _SAFE_MODE_TRUTHY


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_key(cfg: _HookConfig, path: Path, *, writing: bool) -> bytes:
    """The live key, or refuse loudly. Never falls back to plaintext."""
    key = cfg.key
    if key is not None:
        return key
    what = (
        f"refusing to write {path} in plaintext: memory encryption is on but" if writing else f"{path} is encrypted but"
    )
    raise MemoryEncryptionUnavailable(f"{what} {_MEMORY_KEY_ENV} is not set or not usable — {_REMEDY}.")


def _unseal_text(raw: str, *, path: Path, key: bytes) -> str:
    """Open a sealed memory file's text, or raise :class:`MemoryEncryptionUnavailable`."""
    try:
        return unseal(raw.encode("utf-8"), key=key, name=path.name).decode("utf-8")
    except MemoryCryptoError as exc:
        raise MemoryEncryptionUnavailable(
            f"{path} failed to authenticate — it was sealed with a different key, renamed, or "
            f"modified since. Its contents are not recoverable with the current key; {_REMEDY}."
        ) from exc
    except UnicodeDecodeError as exc:
        raise MemoryEncryptionUnavailable(f"{path} decrypted to bytes that are not valid UTF-8.") from exc


def _split_entries(text: str, delimiter: str) -> list[str]:
    """Upstream's entry split, applied to the plaintext we just recovered."""
    return [entry for entry in (part.strip() for part in text.split(delimiter)) if entry]


def _note_plaintext_seen(path: Path) -> None:
    """Warn once per path that a memory file is still plaintext while armed."""
    if str(path) in _PLAINTEXT_SEEN:
        return
    _PLAINTEXT_SEEN.add(str(path))
    logger.warning("%s is plaintext memory while memory encryption is on — it is sealed on the next write", path)


def _write_private(path: Path, data: bytes) -> None:
    """Atomically publish ``data`` at ``path`` through a same-directory temp file.

    Same directory so the rename stays on one filesystem; ``mkstemp`` creates the
    temp at 0o600, so nothing we write is briefly world-readable.
    """
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".mordred_mem_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _seal_file_in_place(path: Path, *, key: bytes) -> None:
    """Seal an existing plaintext file; a no-op when it is already sealed."""
    data = path.read_bytes()
    if is_sealed(data):
        return
    _write_private(path, seal(data, key=key, name=path.name))


# ---------------------------------------------------------------------------
# Seam classification
# ---------------------------------------------------------------------------


def _params(owner: Any, name: str) -> tuple[str, ...] | None:
    member = getattr(owner, name, None)
    if not callable(member):
        return None
    try:
        return tuple(inspect.signature(member).parameters)
    except (TypeError, ValueError):
        return None


def _check_params(owner: Any, name: str, expected: tuple[str, ...]) -> str:
    """``""`` when ``owner.name`` takes exactly ``expected``, else the reason it does not."""
    found = _params(owner, name)
    if found is None:
        return f"MemoryStore.{name} is missing or not callable"
    if found != expected:
        return f"MemoryStore.{name} takes {found} (expected {expected})"
    return ""


def classify_seam(memory_tool_module: Any) -> tuple[str, str]:
    """Classify the upstream seam by signature: ``("A"|"B"|"C", "")`` or ``("", reason)``.

    Never by version string — a vendored or patched ``memory_tool`` can carry any
    version. Anything that does not match a known shape exactly (a rename, a
    renamed parameter, a non-``str`` delimiter, a mixed shape) is unsupported, so
    the caller can fail closed instead of wrapping a seam it does not understand.
    """
    store = getattr(memory_tool_module, "MemoryStore", None)
    if store is None:
        return "", "tools.memory_tool has no MemoryStore"
    if not isinstance(getattr(memory_tool_module, "ENTRY_DELIMITER", None), str):
        return "", "tools.memory_tool.ENTRY_DELIMITER is missing or not a str"

    for name, expected in (("_write_file", ("path", "entries")), ("_read_file", ("path",))):
        reason = _check_params(store, name, expected)
        if reason:
            return "", reason

    if getattr(store, "_read_raw_checked", None) is not None:
        reason = _check_params(store, "_read_raw_checked", ("path",)) or _check_params(
            store, "_detect_external_drift", ("self", "target", "raw")
        )
        return ("", reason) if reason else ("A", "")

    if getattr(store, "_detect_external_drift", None) is None:
        return "C", ""
    reason = _check_params(store, "_detect_external_drift", ("self", "target"))
    return ("", reason) if reason else ("B", "")


def _load_memory_tool() -> tuple[Any | None, str]:
    """Import the live ``tools.memory_tool``, or report why it is unavailable.

    That import has an upstream side effect (it registers the ``memory`` tool in
    the host registry). Acceptable here: ``register()`` runs inside plugin
    discovery, after the host's own tool discovery has already imported it.
    """
    import importlib

    try:
        # importlib rather than `from tools import memory_tool`: `tools` ships no
        # stubs, so the attribute form does not type-check under --strict.
        return importlib.import_module("tools.memory_tool"), ""
    except Exception as exc:
        return None, f"tools.memory_tool is not importable: {exc!r}"


def seam_check(memory_tool_module: Any | None = None) -> tuple[bool, str]:
    """``(True, "")`` when the live seam is one we can wrap, else ``(False, reason)``."""
    module, reason = (memory_tool_module, "") if memory_tool_module is not None else _load_memory_tool()
    if module is None:
        return False, reason
    shape, reason = classify_seam(module)
    return (True, "") if shape else (False, reason)


def memory_seam_shape(memory_tool_module: Any | None = None) -> str:
    """``"A"`` / ``"B"`` / ``"C"``, or ``""`` when unsupported — for diagnostics."""
    module = memory_tool_module if memory_tool_module is not None else _load_memory_tool()[0]
    return "" if module is None else classify_seam(module)[0]


def memory_hook_installed(memory_tool_module: Any | None = None) -> bool:
    """Whether **this process** has the seam wrapped (in-process state, not on-disk)."""
    module = memory_tool_module if memory_tool_module is not None else _load_memory_tool()[0]
    store = getattr(module, "MemoryStore", None) if module is not None else None
    return store is not None and _is_wrapped(store, "_write_file")


# ---------------------------------------------------------------------------
# Wrappers
# ---------------------------------------------------------------------------


def _is_wrapped(store: Any, name: str) -> bool:
    return bool(getattr(getattr(store, name, None), _WRAPPED_FLAG, False))


def _publish(store: Any, name: str, wrapper: Any, *, static: bool) -> None:
    """Stamp and install ``wrapper``.

    ``static=True`` re-wraps in ``staticmethod``: the upstream seams are static,
    and a plain function assigned back would bind ``self`` to the first argument
    on every instance call.
    """
    setattr(wrapper, _WRAPPED_FLAG, True)
    setattr(store, name, staticmethod(wrapper) if static else wrapper)


def _wrap_write_file(store: Any, cfg: _HookConfig) -> None:
    original = store._write_file

    @functools.wraps(original)
    def _write_file(path: Path, entries: list[str]) -> Any:
        if not cfg.armed:
            return original(path, entries)
        key = _require_key(cfg, path, writing=True)
        content = cfg.delimiter.join(entries) if entries else ""
        sealed = seal(content.encode("utf-8"), key=key, name=path.name)
        # Hand the blob back as a ONE-entry list: `delimiter.join([x]) == x`, so
        # upstream's atomic write and its OSError -> RuntimeError translation are
        # reused verbatim instead of reimplemented here.
        return original(path, [sealed.decode("ascii")])

    _publish(store, "_write_file", _write_file, static=True)


def _wrap_read_raw_checked(store: Any, cfg: _HookConfig) -> None:
    """Shape A: the single checked read every mutation path derives its snapshot from."""
    original = store._read_raw_checked

    @functools.wraps(original)
    def _read_raw_checked(path: Path) -> tuple[str, bool]:
        raw, read_ok = original(path)
        if not read_ok or not raw:
            return raw, read_ok  # absent / unreadable: upstream's contract is untouched
        if is_sealed(raw):
            return _unseal_text(raw, path=path, key=_require_key(cfg, path, writing=False)), True
        if cfg.armed:
            _note_plaintext_seen(path)
        return raw, True

    _publish(store, "_read_raw_checked", _read_raw_checked, static=True)


def _wrap_read_file(store: Any, cfg: _HookConfig) -> None:
    """Shapes B/C: ``_read_file`` is the only read, for both loading and mutating.

    Limitation: in B/C upstream returns ``[]`` for both "absent" and "unreadable",
    so a read failure on a *plaintext* file stays indistinguishable from an empty
    store — the hook cannot add a safety net upstream itself lacks. A sealed file
    is covered, because it can never decode to ``[]``.
    """
    original = store._read_file

    @functools.wraps(original)
    def _read_file(path: Path) -> list[str]:
        entries: list[str] = original(path)
        # A sealed file holds no delimiter, so it always parses as exactly one
        # entry — already stripped by upstream, which `unseal` tolerates.
        if len(entries) == 1 and is_sealed(entries[0]):
            plaintext = _unseal_text(entries[0], path=path, key=_require_key(cfg, path, writing=False))
            return _split_entries(plaintext, cfg.delimiter)
        if entries and cfg.armed:
            _note_plaintext_seen(path)
        return entries

    _publish(store, "_read_file", _read_file, static=True)


def _wrap_drift_on_snapshot(store: Any, cfg: _HookConfig) -> None:
    """Shape A: upstream already sees plaintext (the read wrapper opened it).

    Only the ``.bak`` snapshot it writes needs sealing — upstream writes it with a
    raw ``Path.write_text``, which would leave recovered memory in the clear.
    """
    original = store._detect_external_drift

    @functools.wraps(original)
    def _detect_external_drift(self: Any, target: str, raw: str) -> Any:
        result = original(self, target, raw)
        _seal_drift_backup(result, cfg)
        return result

    _publish(store, "_detect_external_drift", _detect_external_drift, static=False)


def _seal_drift_backup(result: Any, cfg: _HookConfig) -> None:
    """Best-effort seal of the backup upstream just wrote (a failure must not abort the mutation)."""
    if not isinstance(result, str) or not cfg.armed:
        return
    key = cfg.key
    if key is None:
        return
    path = Path(result)
    try:
        # The "(BACKUP FAILED …)" result is not a path that exists — nothing to seal.
        if path.is_file():
            _seal_file_in_place(path, key=key)
    except (OSError, MemoryCryptoError) as exc:
        logger.warning("could not seal the memory drift backup %s: %s", path, exc)


def _wrap_drift_self_read(store: Any, cfg: _HookConfig) -> None:
    """Shape B: upstream re-reads the file itself, so it would judge the *sealed* bytes.

    Base64 expansion alone pushes a sealed file past the store's char limit, which
    upstream reads as an oversize entry — every ``replace`` / ``remove`` would be
    refused with a spurious drift error. So for a sealed file we replicate
    upstream's two drift signals on the plaintext, and seal the backup we write.
    """
    original = store._detect_external_drift

    @functools.wraps(original)
    def _detect_external_drift(self: Any, target: str) -> Any:
        path = Path(self._path_for(target))
        raw = _sealed_text_at(path)
        if raw is None:
            return original(self, target)  # absent / unreadable / plaintext: upstream logic intact
        key = _require_key(cfg, path, writing=False)
        plaintext = _unseal_text(raw, path=path, key=key)
        return _drift_on_plaintext(self, target, path, plaintext, cfg=cfg, key=key)

    _publish(store, "_detect_external_drift", _detect_external_drift, static=False)


def _sealed_text_at(path: Path) -> str | None:
    """The file's text when it exists and is sealed, else ``None``."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return raw if is_sealed(raw) else None


def _drift_on_plaintext(
    store: Any,
    target: str,
    path: Path,
    plaintext: str,
    *,
    cfg: _HookConfig,
    key: bytes,
) -> str | None:
    """Upstream's drift check, run on the decrypted text; returns its ``.bak`` contract."""
    parsed = _split_entries(plaintext, cfg.delimiter)
    roundtrip = cfg.delimiter.join(parsed)
    max_entry_len = max((len(entry) for entry in parsed), default=0)
    if plaintext.strip() == roundtrip and max_entry_len <= store._char_limit(target):
        return None

    bak_path = path.with_suffix(path.suffix + f".bak.{int(time.time())}")
    try:
        _write_private(bak_path, seal(plaintext.encode("utf-8"), key=key, name=bak_path.name))
    except OSError:
        return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
    return str(bak_path)


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------


def _wrap_seam(store: Any, shape: str, cfg: _HookConfig) -> None:
    """Wrap every seam of ``shape`` that is not wrapped already."""
    if not _is_wrapped(store, "_write_file"):
        _wrap_write_file(store, cfg)
    if shape == "A":
        if not _is_wrapped(store, "_read_raw_checked"):
            _wrap_read_raw_checked(store, cfg)
        if not _is_wrapped(store, "_detect_external_drift"):
            _wrap_drift_on_snapshot(store, cfg)
        return
    if not _is_wrapped(store, "_read_file"):
        _wrap_read_file(store, cfg)
    if shape == "B" and not _is_wrapped(store, "_detect_external_drift"):
        _wrap_drift_self_read(store, cfg)


def install_memory_hook(
    *,
    home: Path | None = None,
    memory_tool_module: Any | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Wrap the upstream memory seam for this process. Returns whether it is wrapped.

    Called from the keyvault plugin ``register()``, which runs before the first
    disk-touching ``MemoryStore`` for every ``run_agent``-driven entry point.
    Idempotent.

    * ``HERMES_SAFE_MODE`` truthy → no-op (the operator's recovery escape hatch).
    * Unsupported seam **and not armed** → ``False``: Hermes runs exactly as it
      does today, in plaintext. Nothing is at risk because nothing is sealed.
    * Unsupported seam **while armed** → ``SystemExit(1)``. Sealed memories are on
      disk and we cannot open them; starting would let upstream treat them as
      garbage and overwrite them. ``SystemExit`` because upstream only debug-logs
      exceptions raised from ``register()``.
    """
    environ = os.environ if environ is None else environ
    if _safe_mode(environ):
        return False
    home = _hermes_home() if home is None else home

    module, load_reason = (memory_tool_module, "") if memory_tool_module is not None else _load_memory_tool()
    if module is None:
        _refuse_or_ignore(load_reason, home=home, environ=environ)
        return False
    shape, reason = classify_seam(module)
    if not shape:
        _refuse_or_ignore(reason, home=home, environ=environ)
        return False

    cfg = _HookConfig(home=home, environ=environ, delimiter=module.ENTRY_DELIMITER)
    _wrap_seam(module.MemoryStore, shape, cfg)
    return True


def _refuse_or_ignore(reason: str, *, home: Path, environ: Mapping[str, str]) -> None:
    """Fail closed on an unsupported seam only when memory encryption is actually on."""
    armed = memory_marker_path(home).exists() and not memory_optout_marker_path(home).exists()
    if not armed:
        return
    sys.stderr.write(
        "mordred: refusing to start — memory encryption is on but the Hermes memory seam "
        f"cannot be wrapped: {reason} (set HERMES_SAFE_MODE=1 to bypass for recovery)\n"
    )
    raise SystemExit(1)


def _main(argv: Sequence[str] | None = None) -> int:
    """``python -m mordred_hermes.keyvault._memory_hook --probe``.

    Answers "can this interpreter wrap the memory seam?" with an exit code and no
    side effects — no vault access, no prompts. Used by the runtime probe.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if args != ["--probe"]:
        sys.stderr.write("usage: python -m mordred_hermes.keyvault._memory_hook --probe\n")
        return 2
    ok, reason = seam_check()
    if not ok:
        sys.stderr.write(f"{reason}\n")
        return 1
    sys.stdout.write(f"{memory_seam_shape()}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(_main())
