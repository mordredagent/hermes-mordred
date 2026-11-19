"""Mordred Extension state on the Hermes side: the master key.

Browsers no longer pair with codes: they are approved with a signature by the
vault approval key (:mod:`.trust`). What stays here is Hermes' own state under
``~/.hermes/extension/`` with ``0600`` permissions:

- ``state.json`` — Hermes' master key (``aes_key``: chat history and the
  encrypt/decrypt oracle). The master is created at the first browser approval
  (:func:`ensure_master`) and never leaves Hermes. Fields left by the removed
  Slack/Discord transport (``channel_keys``, ``e2e_replay_v3``) are kept as they
  are and no longer read.

On Windows these files live in a checked private directory instead
(:mod:`._windows_storage`): the ``.mordred-fs.lock`` transaction replaces the
``.lock`` flock, every read is bounded and identity-bound, and unsafe state is
refused rather than repaired or treated as absent.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import stat
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from .._core._file_lock import private_flock
from .._private_fs import FileIdentity
from ..keyvault._storage import atomic_write, safe_read
from . import _windows_storage as _storage
from .crypto import b64u_decode, b64u_encode

_LOG = logging.getLogger("mordred.extension.pairing")
_STATE_THREAD_LOCK = threading.RLock()


@contextlib.contextmanager
def _tolerated_storage_failure(what: str) -> Iterator[None]:
    """Log, never raise, a checked-storage failure of best-effort metadata.

    Used exactly where POSIX already suppresses ``OSError`` because another
    record is authoritative. The classification is logged without contents.
    """
    try:
        yield
    except _storage.ExtensionStorageError as exc:
        _LOG.warning("%s was not saved (%s, %s)", what, exc.reason, exc.commit_state)


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def _ext_dir() -> Path:
    from .._core._home import hermes_home

    d = hermes_home() / "extension"
    if _storage.enabled():
        # Admission, creation of the final directory and ACL validation happen
        # inside the checked session; never lstat/mkdir/chmod the path here.
        return d
    try:
        metadata = d.lstat()
    except FileNotFoundError:
        with contextlib.suppress(FileExistsError):
            d.mkdir(mode=0o700, parents=True)
        metadata = d.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError("extension state directory must be a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        os.chmod(d, 0o700, follow_symlinks=False)
    return d


def _write_private(path: Path, data: bytes) -> None:
    """0600 atomic write, delegated to the keyvault's canonical helper.

    These files hold Hermes' master key and the channel keys — the same class
    of secret the keyvault protects — so they get
    the same guarantees instead of a hand-rolled, weaker copy: unpredictable tmp
    name, ``O_EXCL | O_NOFOLLOW`` (no symlink follow / tmp pre-planting), fsync
    of the tmp fd *and* the parent dir, and tmp cleanup on failure. The parent
    directory always exists here — every caller resolves its path through
    :func:`_ext_dir`, which mkdirs it.

    On Windows this is the checked create-or-replace of
    :func:`._windows_storage.write_file` instead."""
    if _storage.enabled():
        _storage.write_file(path, data)
        return
    atomic_write(path, data)


def _read_json(path: Path) -> dict[str, Any]:
    """Read a private JSON-object store, tolerating only genuine absence.

    An absent store is the normal first-run state and remains represented by
    ``{}`` for compatibility with the existing callers.  Once a directory
    entry exists, however, treating an unreadable, unsafe, malformed, or
    non-object file as empty would let the next read-modify-write silently
    replace pairing credentials, pending-code evidence, or channel keys.
    Existing bad state therefore fails closed and is left byte-for-byte intact.
    On Windows only the checked absence is ``{}``; storage refusals raise
    :class:`._windows_storage.ExtensionStorageError`.
    """
    if _storage.enabled():
        checked = _storage.read_file(path)
        if checked is None:
            return {}
        raw = checked
    else:
        try:
            raw = safe_read(path)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise RuntimeError(f"extension JSON store {path.name} is unreadable or corrupt") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"extension JSON store {path.name} is unreadable or corrupt") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"extension JSON store {path.name} is unreadable or corrupt")
    return data


def _read_json_strict(path: Path, purpose: str) -> dict[str, Any]:
    """Read a private JSON object, distinguishing missing/corrupt from empty."""
    if _storage.enabled():
        checked = _storage.read_file(path)
        if checked is None:
            raise RuntimeError(f"{purpose} is missing, unreadable, or corrupt")
        try:
            data = json.loads(checked.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError(f"{purpose} is missing, unreadable, or corrupt") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"{purpose} is missing, unreadable, or corrupt")
        return data
    try:
        raw = safe_read(path)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"{purpose} is missing, unreadable, or corrupt") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{purpose} is missing, unreadable, or corrupt")
    return data


def _reject_unsafe_state_lock(_lock_path: Path) -> NoReturn:
    """Fail closed when ``.lock`` is not a private regular file.

    Kept in this module (rather than inside ``private_flock``) so the raised
    exception stays byte-identical: a single-argument :exc:`OSError` with no
    ``errno``, unlike the ``EPERM``-tagged three-argument form the wizard
    writers raise.
    """
    raise OSError("extension state lock must be a mode-0600 regular file")


@contextlib.contextmanager
def _state_lock() -> Iterator[None]:
    """Cross-process mutex for read-modify-write cycles on the JSON stores.

    Concurrent processes (the gateway, the CLI) mutate ``state.json``
    / ``state.json`` from different processes; without this, interleaved
    read→write cycles lose updates — e.g. two racing ``pair_init`` frames could
    both consume the same one-time code. Locked sections must stay synchronous
    (no awaits): callers run on the gateway's event loop and rely on the lock
    being held only for a quick file round-trip.

    The descriptor lifecycle (private ``O_NOFOLLOW`` open, mode-0600 assertion
    on the opened inode, ``flock`` / unlock / close ordering) is
    :func:`mordred_hermes._core._file_lock.private_flock`; ``_ext_dir()`` still owns
    creating and validating the parent directory, and the raise in
    :func:`_reject_unsafe_state_lock` still happens in this module so its
    exact one-argument :exc:`OSError` is unchanged.

    On Windows the mutex is the checked ``<home>/extension`` transaction
    (``.mordred-fs.lock``, shared with the wallet selection); ``.lock`` is never
    created there. Nested same-thread calls reuse that one transaction.
    """
    if _storage.enabled():
        with _storage.session(_ext_dir(), create=True):
            yield
        return
    with _STATE_THREAD_LOCK, private_flock(_ext_dir() / ".lock", on_unsafe=_reject_unsafe_state_lock):
        yield


# --------------------------------------------------------------------------- #
# Secure-Enclave capability probe
# --------------------------------------------------------------------------- #


def se_available() -> bool:
    try:
        from mordred_hermes.keyvault import native

        return bool(native.is_secure_enclave_available())
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Active pairing state
# --------------------------------------------------------------------------- #


@dataclass
class Pairing:
    aes_key: bytes
    ext_token: str
    ext_pubkey_b64: str
    hermes_pubkey_b64: str
    paired_at: float


def _state_path() -> Path:
    return _ext_dir() / "state.json"


# --------------------------------------------------------------------------- #
# state.json parse cache
# --------------------------------------------------------------------------- #
#
# state.json carries the E2E replay cache (up to _E2E_REPLAY_MAX_IDENTITIES
# entries, several MB at capacity) alongside the pairing key and channel keys.
# Every authenticated WS frame reads it at least once — _authentication_is_current
# fingerprints the active pairing on every authed dispatch (extension_api.py) —
# so a bare _read_json(_state_path()) per frame put a multi-millisecond
# json.loads on the gateway's single-threaded event loop for every message
# (review 2026-08-02, PR #88 follow-up).
#
# The cache is keyed on (path, mtime_ns, size) rather than a manual dirty flag:
# the path is included because HERMES_HOME — hence state.json's location — can
# change within a process (the test suite's per-test isolated homes); mtime/size
# because that is cheap to check on every access (a stat, not a parse) and also
# catches a state.json rewritten by another process or restored from backup,
# not just this module's own writes. Every write path this module owns
# additionally calls _invalidate_state_cache() explicitly right after the write
# commits, so a fresh read is never gated on the filesystem's mtime resolution
# actually advancing between two writes issued back-to-back.
#
# That explicit invalidation only holds against a concurrent reader because of
# the generation counter below. Readers deliberately do NOT take _state_lock()
# (skipping it is the point of the fast path), so a reader can stat and parse a
# pre-write state.json, get descheduled, and only reach its cache store after a
# writer has already invalidated — re-publishing the snapshot the invalidation
# was meant to retire. Storing only when the generation is unchanged since the
# read began makes a raced read fall back to leaving the cache cold, so the
# next reader re-parses instead of trusting mtime to have advanced.
#
# Only READ-ONLY consumers of the parsed dict may use _read_state_cached(): it
# can hand back the very same dict object to multiple callers, so a read-modify
# -write cycle (_write_pairing_locked) must keep reading via the uncached _read_json /
# _read_json_strict — mutating the cached dict in place would let a concurrent
# reader observe an uncommitted write before it reaches disk.
_STATE_CACHE_LOCK = threading.Lock()
_state_cache: tuple[Path, int, int, dict[str, Any]] | None = None
_state_cache_generation = 0
# Windows: the key is the checked directory and file identity plus size and
# mtime, re-validated (ACL, links, reparse) by a checked stat on every read.
_CheckedStateKey = tuple[Path, FileIdentity, FileIdentity, int, int]
_checked_state_cache: tuple[_CheckedStateKey, dict[str, Any]] | None = None


def _state_stat_key() -> tuple[Path, int, int] | None:
    """(path, mtime_ns, size) identifying the on-disk state.json, or ``None``
    if it does not currently exist."""
    path = _state_path()
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (path, st.st_mtime_ns, st.st_size)


def _invalidate_state_cache() -> None:
    global _state_cache, _checked_state_cache, _state_cache_generation
    with _STATE_CACHE_LOCK:
        _state_cache = None
        _checked_state_cache = None
        _state_cache_generation += 1


def _read_state_cached() -> dict[str, Any]:
    """Read-only, cached equivalent of ``_read_json(_state_path())``."""
    global _state_cache
    if _storage.enabled():
        return _read_checked_state_cached()
    key = _state_stat_key()
    with _STATE_CACHE_LOCK:
        cached = _state_cache
        generation = _state_cache_generation
    if key is not None and cached is not None and (cached[0], cached[1], cached[2]) == key:
        return cached[3]
    data = _read_json(_state_path())
    with _STATE_CACHE_LOCK:
        if _state_cache_generation != generation:
            # A write committed while we were parsing: `data` may predate it,
            # and `key` certainly does. Leave the cache cold rather than
            # publish a snapshot the writer already invalidated.
            _state_cache = None
        else:
            _state_cache = (key[0], key[1], key[2], data) if key is not None else None
    return data


def _read_checked_state_cached() -> dict[str, Any]:
    """Windows: a checked stat under the lock revalidates every cache hit.

    Security drift (ACL, link count, reparse) refuses at the stat, so a cached
    dict is never served for state that is no longer admissible, and a
    replaced file has a new identity even when size and mtime match.
    """
    global _checked_state_cache
    path = _state_path()
    with _storage.session(path.parent, create=False) as active:
        metadata = active.stat(path.name)
        if metadata is None:
            return {}
        key = (path, active.directory_identity(), metadata.identity, metadata.size, metadata.mtime_ns)
        with _STATE_CACHE_LOCK:
            cached = _checked_state_cache
            generation = _state_cache_generation
        if cached is not None and cached[0] == key:
            return cached[1]
        data = _read_json(path)
        with _STATE_CACHE_LOCK:
            if _state_cache_generation != generation or active.bound(path.name) != metadata.identity:
                _checked_state_cache = None
            else:
                _checked_state_cache = (key, data)
        return data


def load_pairing() -> Pairing | None:
    data = _read_state_cached()
    if not data or "aes_key" not in data:
        return None
    return Pairing(
        aes_key=b64u_decode(data["aes_key"]),
        ext_token=data.get("ext_token", ""),
        ext_pubkey_b64=data.get("ext_pubkey", ""),
        hermes_pubkey_b64=data.get("hermes_pubkey", ""),
        paired_at=data.get("paired_at", 0.0),
    )


def _write_pairing_locked(p: Pairing) -> None:
    """Persist *p* while the caller holds :func:`_state_lock`."""
    # Preserve any other fields already in state.
    data = _read_json(_state_path()) or {}
    data.update(
        {
            "aes_key": b64u_encode(p.aes_key),
            "ext_token": p.ext_token,
            "ext_pubkey": p.ext_pubkey_b64,
            "hermes_pubkey": p.hermes_pubkey_b64,
            "paired_at": p.paired_at,
        }
    )
    _write_private(_state_path(), json.dumps(data).encode("utf-8"))
    _invalidate_state_cache()


def _save_pairing(p: Pairing) -> None:
    with _state_lock():
        _write_pairing_locked(p)


def ensure_master() -> Pairing:
    """Hermes' master key, created on first use. It never leaves Hermes."""
    with _state_lock():
        current = load_pairing()
        if current is not None:
            return current
        created = Pairing(
            aes_key=secrets.token_bytes(32),
            ext_token="",
            ext_pubkey_b64="",
            hermes_pubkey_b64="",
            paired_at=time.time(),
        )
        _write_pairing_locked(created)
        return created


# NOTE: there is deliberately no load/save_extchat_key here. K_extchat is always
# DERIVED fresh from the pairing master key (``api._extchat_key`` →
# ``hkdf_subkey``); a persisted copy was written and read by nobody and would
# only invite a derive-vs-stored mismatch after a re-pair.


def clear_pairing() -> None:
    if _storage.enabled():
        # Revocation must not be silently partial: checked deletion refuses
        # unsafe state instead of suppressing it, and never creates the
        # directory just to find nothing to delete.
        try:
            with _storage.session(_ext_dir(), create=False):
                for name in ("state.json", "webauthn.json"):
                    _storage.delete_file(_ext_dir() / name)
        finally:
            _invalidate_state_cache()
        return
    with _state_lock():
        for name in ("state.json", "webauthn.json"):
            with _suppress_oserror():
                (_ext_dir() / name).unlink()
        _invalidate_state_cache()


class _suppress_oserror:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, *_: Any) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)
