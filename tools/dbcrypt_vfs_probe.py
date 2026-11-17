#!/usr/bin/env python3
"""Diagnostic same-library VFS feasibility with synthetic data, never a Hermes home."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

VFS_NAME = "mordred_probe_v1"
CALLBACKS = frozenset({"xOpen", "xDelete", "xShmMap", "xShmUnmap"})


class ProbeRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    wheel_version: str
    sqlite_version: str
    sqlcipher_version: str
    extension_loaded: bool
    persistent: bool
    selected_vfs: str
    callbacks: tuple[str, ...]
    same_library: bool
    shm_boundary_viable: bool

    @property
    def passed(self) -> bool:
        return (
            all((self.extension_loaded, self.persistent, self.same_library, self.shm_boundary_viable))
            and self.selected_vfs == VFS_NAME
            and set(self.callbacks) >= CALLBACKS
        )


def _report(path: Path, payload: dict[str, Any]) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".dbcrypt-probe-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def loaded_modules() -> list[str] | None:
    try:
        import psutil
    except ImportError:
        return None
    try:
        return sorted({row.path for row in psutil.Process().memory_maps()})
    except (OSError, AttributeError, psutil.Error):
        return None


def _stats(connection: Any) -> dict[str, Any]:
    value = json.loads(connection.execute("SELECT mordred_probe_stats()").fetchone()[0])
    if not isinstance(value, dict):
        raise ProbeRefused("invalid_probe_counters")
    return value


def _bootstrap(driver: Any, extension: Path) -> tuple[str, str]:
    connection = driver.connect(":memory:")
    try:
        connection.enable_load_extension(True)
        try:
            connection.execute("SELECT load_extension(?, ?)", (str(extension), "sqlite3_mordredprobe_init"))
        finally:
            connection.enable_load_extension(False)
        source_id = connection.execute("SELECT sqlite_source_id()").fetchone()[0]
        return source_id, connection.execute("PRAGMA cipher_version").fetchone()[0]
    finally:
        connection.close()


@contextlib.contextmanager
def keyed_connection(driver: Any, path: Path, key: Any) -> Iterator[Any]:
    from mordred_hermes.dbcrypt._shim import apply_key

    connection = driver.connect(path.resolve().as_uri() + f"?vfs={VFS_NAME}", uri=True)
    try:
        apply_key(connection, key)
        connection.execute("PRAGMA temp_store=MEMORY")
        yield connection
    finally:
        connection.close()


def _write_and_reopen(driver: Any, path: Path, key: Any) -> str:
    with keyed_connection(driver, path, key) as connection:
        selected = connection.execute("SELECT mordred_probe_vfs()").fetchone()[0]
        if not selected.startswith(VFS_NAME + "/"):
            raise ProbeRefused("unexpected_vfs")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("CREATE TABLE messages (text TEXT)")
        connection.execute("CREATE VIRTUAL TABLE search USING fts5(text, tokenize='trigram')")
        connection.execute("INSERT INTO messages VALUES ('synthetic 日本語 りんご')")
        connection.execute("INSERT INTO search SELECT text FROM messages")
        connection.commit()
        if connection.execute("SELECT text FROM search WHERE search MATCH '日本語'").fetchone() != (
            "synthetic 日本語 りんご",
        ):
            raise ProbeRefused("fts_roundtrip_failed")
        if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
            raise ProbeRefused("wal_unavailable")
        connection.execute("INSERT INTO messages VALUES ('WAL retention')")
        connection.commit()
    with keyed_connection(driver, path, key) as connection:
        if connection.execute("SELECT count(*) FROM messages").fetchone() != (2,):
            raise ProbeRefused("reopen_roundtrip_failed")
    # Same library and all writers closed: do not introduce the POSIX lock hazard.
    keyless = driver.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        try:
            keyless.execute("SELECT text FROM messages").fetchall()
        except (driver.Error, UnicodeDecodeError, MemoryError):
            pass
        else:
            raise ProbeRefused("keyless_read_succeeded")
    finally:
        keyless.close()
    return str(selected)


def _deny_mapping(driver: Any, control: Any, path: Path, key: Any) -> bool:
    blocked = False
    before = _stats(control)
    control.execute("SELECT mordred_probe_deny_shm(1)")
    try:
        with keyed_connection(driver, path, key) as connection:
            connection.execute("INSERT INTO messages VALUES ('must be refused')")
            connection.commit()
    except driver.Error:
        blocked = True
    finally:
        control.execute("SELECT mordred_probe_deny_shm(0)")
    after = _stats(control)
    with keyed_connection(driver, path, key) as connection:
        if connection.execute("SELECT count(*) FROM messages").fetchone() != (2,):
            raise ProbeRefused("denied_write_committed")
    return blocked and after["shmDenied"] > before["shmDenied"] and after["shmDelegations"] == before["shmDelegations"]


def probe(*, output: Path, extension: Path | None = None) -> ProbeResult:
    if extension is None:
        configured = os.environ.get("MORDRED_DBCRYPT_PROBE_LIBRARY")
        extension = Path(configured) if configured else None
    if extension is None or extension.is_symlink() or not extension.is_file():
        raise ProbeRefused("extension_unavailable")
    import sqlcipher3.dbapi2 as driver

    import mordred_hermes
    from mordred_hermes.dbcrypt._key import derive

    extension = extension.resolve()
    source_id, cipher_version = _bootstrap(driver, extension)
    control = driver.connect(":memory:")
    try:
        # The bootstrap connection is closed: functions and VFS must persist.
        if _stats(control)["source_id"] != source_id:
            raise ProbeRefused("extension_library_mismatch")
        with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-probe-", dir=output.parent) as temporary:
            path = Path(temporary) / "synthetic.db"
            key = derive(bytes(range(32)))  # Public synthetic input, never native custody.
            selected = _write_and_reopen(driver, path, key)
            boundary = _deny_mapping(driver, control, path, key)
        counters = _stats(control)
    finally:
        control.close()
    result = ProbeResult(
        wheel_version=importlib.metadata.version("sqlcipher3-wheels"),
        sqlite_version=driver.sqlite_version,
        sqlcipher_version=cipher_version,
        extension_loaded=True,
        persistent=True,
        selected_vfs=VFS_NAME,
        callbacks=tuple(sorted(name for name in CALLBACKS if counters.get(name, 0) > 0)),
        same_library=source_id == counters["source_id"],
        shm_boundary_viable=boundary,
    )
    _report(
        output,
        dict(
            version=1,
            passed=result.passed,
            result=asdict(result),
            platform=platform.platform(),
            python=sys.executable,
            product_module=mordred_hermes.__file__,
            driver_module=driver.__file__,
            extension=str(extension),
            extension_sha256=hashlib.sha256(extension.read_bytes()).hexdigest(),
            selected_vfs_chain=selected,
            counters=counters,
            encryption_verified=True,
            fts_japanese_verified=True,
            bootstrap_closed=True,
            shm_denial_verified=boundary,
            production_filesystem_acceptance=False,
            loaded_modules=loaded_modules(),
        ),
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--extension", type=Path)
    args = parser.parse_args(argv)
    try:
        result = probe(output=args.output, extension=args.extension)
        print(json.dumps({"passed": result.passed, "output": str(args.output)}))
        return 0 if result.passed else 1
    except Exception as exc:
        code = str(exc) if isinstance(exc, ProbeRefused) else type(exc).__name__
        _report(args.output, {"version": 1, "passed": False, "error": code, "production_filesystem_acceptance": False})
        print(json.dumps({"passed": False, "error": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
