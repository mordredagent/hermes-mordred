"""Public recovery observations and bounded keyvault file retirement."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any

from .._core._database_contracts import DatabaseRefused
from . import _storage

STAGES = ("database", "mail", "telegram", "keys", "files", "complete")


def observation(path: Path) -> list[Any] | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    directory = stat.S_ISDIR(before.st_mode)
    if (
        not (directory or stat.S_ISREG(before.st_mode))
        or before.st_uid != os.getuid()
        or before.st_mode & 0o022
        or (not directory and before.st_nlink != 1)
    ):
        raise DatabaseRefused("reset path is unsafe; recovery evidence retained")
    digest = None
    if not directory:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if os.fstat(fd) != before:
                raise DatabaseRefused("reset file changed before read")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
        finally:
            os.close(fd)
    after = path.lstat()

    def stable(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    if stable(before) != stable(after):
        raise DatabaseRefused("reset path changed while observing it")
    return [before.st_dev, before.st_ino, before.st_mode, before.st_uid, digest]


def _known_file(relative: str, key_ids: dict[str, str]) -> bool:
    if relative in {"meta.json", ".lock"}:
        return True
    hashes = {hashlib.sha256(key.encode()).digest()[:16].hex() for key in key_ids}
    parts = Path(relative).parts
    if len(parts) == 2 and parts[0] == "digests":
        return parts[1].endswith(".commit") and parts[1][:-7] in hashes
    return (
        len(parts) == 4
        and parts[0] == "ciphertexts"
        and parts[1] in hashes
        and re.fullmatch(r"[0-9a-f]{32}", parts[2]) is not None
        and re.fullmatch(r"[A-Za-z0-9_-]{22}\.gcm", parts[3]) is not None
    )


def snapshot_files(root: Path, key_ids: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    from ._mail_key import KEY_ID as MAIL
    from ._seckey_errors import _application_tag
    from ._telegram_custody import KEY_ID as TELEGRAM

    target_blobs = {
        f"{leaf}/{_application_tag(selector).hex()}.bin"
        for leaf in ("sekey", "tpm")
        for selector in (*key_ids.values(), MAIL, TELEGRAM)
    }
    remove: dict[str, Any] = {}
    keep: dict[str, Any] = {}
    if not root.exists():
        return remove, keep
    # Never follow directory aliases, including unknown helper paths.
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in (*directories, *files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            seen = observation(path)
            if relative in target_blobs:
                continue  # only authenticated component/native deletion owns these
            if _known_file(relative, key_ids):
                remove[relative] = seen
            elif name not in {".lock"} and not path.is_dir():
                keep[relative] = seen
            elif path.is_dir():
                keep[relative + "/"] = seen
    return remove, keep


def _valid_observation(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 5
        and all(type(item) is int and item >= 0 for item in value[:4])
        and (value[4] is None or (isinstance(value[4], str) and re.fullmatch(r"[0-9a-f]{64}", value[4]) is not None))
    )


def validate_connected(root: Path, value: Any, key_ids: dict[str, str]) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"home", "home_identity", "stage", "remove", "keep", "sources", "credentials", "native"}
        or value["home"] != str(root.parent.parent)
        or value["stage"] not in STAGES
        or not _valid_observation(value["home_identity"])
        or not all(isinstance(value[k], dict) for k in ("remove", "keep", "sources", "credentials", "native"))
    ):
        raise _storage.KeyvaultCorruptError("connected reset journal has invalid scope or progress")
    required = {"key:" + key for key in key_ids}
    if not required <= set(value["native"]) <= required | {"mail", "telegram"} or any(
        not isinstance(v, str) or v not in {"pending", "deleting", "deleted"} for v in value["native"].values()
    ):
        raise _storage.KeyvaultCorruptError("connected reset journal has invalid native progress")
    for group in ("remove", "keep", "sources", "credentials"):
        for name, seen in value[group].items():
            if (
                not isinstance(name, str)
                or not name
                or Path(name).is_absolute()
                or ".." in Path(name).parts
                or (seen is not None and not _valid_observation(seen))
                or (group == "remove" and not _known_file(name, key_ids))
            ):
                raise _storage.KeyvaultCorruptError("connected reset journal has invalid path observations")


def known_directory(relative: str, key_ids: dict[str, str]) -> bool:
    parts = Path(relative).parts
    hashes = {hashlib.sha256(key.encode()).digest()[:16].hex() for key in key_ids}
    return relative in {"digests", "ciphertexts"} or (
        len(parts) in {2, 3}
        and parts[0] == "ciphertexts"
        and parts[1] in hashes
        and (len(parts) == 2 or re.fullmatch(r"[0-9a-f]{32}", parts[2]) is not None)
    )


def check_observations(base: Path, expected: dict[str, Any], *, missing_ok: bool = False) -> None:
    for relative, seen in expected.items():
        # Check each ancestor before touching a leaf; a substituted directory
        # must not redirect deletion into a different tree.
        path = base / relative.rstrip("/")
        for parent in reversed(path.parents):
            if (parent == base or parent.is_relative_to(base)) and (parent.exists() or parent.is_symlink()):
                if parent == base:
                    parent_observation = observation(parent)
                    if parent_observation is None or not stat.S_ISDIR(parent_observation[2]):
                        raise DatabaseRefused("reset observation base is not a safe directory")
                else:
                    _storage._check_dir_mode(parent)
        current = observation(path)
        if current != seen and not (missing_ok and current is None):
            raise DatabaseRefused("reset target or retained source changed; recovery evidence retained")


def remove_known_files(root: Path, key_ids: dict[str, str], state: dict[str, Any]) -> None:
    check_observations(root, state["remove"], missing_ok=True)
    for relative, seen in state["remove"].items():
        if not _known_file(relative, key_ids):
            raise DatabaseRefused("reset journal names a file without checked keyvault ownership")
        path = root / relative
        if observation(path) is not None:
            check_observations(root, {relative: seen})
            path.unlink()
            _storage.fsync_keyvault_parent(path)
    # Only empty, validated known layout directories may be removed. Helpers
    # and unknown files keep their parents; there is deliberately no rmtree.
    if root.exists():
        directories = [p for p in root.rglob("*") if p.is_dir() and not p.is_symlink()]
        for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
            relative = path.relative_to(root).as_posix()
            if not known_directory(relative, key_ids):
                continue
            with contextlib.suppress(OSError):
                path.rmdir()
        with contextlib.suppress(OSError):
            root.rmdir()
    _storage.fsync_keyvault_parent(root)
